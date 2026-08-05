use std::{fmt, future::Future, pin::Pin};

use serde_json::{Value, json};

use crate::cln::{
    ClnClient, ClnError, ClnRequestId, IMMORTAL_REGTEST_HOLD_METHOD, InvoiceResult, Millisatoshi,
    PaymentResult, ReleasedPaymentPreimage,
};

pub type LightningFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, LightningError>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightningError {
    rail: &'static str,
    detail: String,
    transient: bool,
}

impl LightningError {
    fn cln(error: ClnError) -> Self {
        let transient = matches!(
            error,
            ClnError::ConnectionFailed
                | ClnError::TimedOut(_)
                | ClnError::Io(_)
                | ClnError::Rpc { .. }
                | ClnError::Unsynced(_)
        );
        Self {
            rail: "CLN",
            detail: error.to_string(),
            transient,
        }
    }

    #[cfg(feature = "lnd")]
    fn lnd(error: crate::lnd::LndError) -> Self {
        use crate::lnd::LndError;
        let transient = matches!(
            error,
            LndError::ResolutionFailed
                | LndError::ConnectionFailed
                | LndError::TimedOut(_)
                | LndError::Io(_)
                | LndError::HttpStatus(_)
                | LndError::Rpc(_)
                | LndError::Json("LND is not synchronized")
        );
        Self {
            rail: "LND",
            detail: error.to_string(),
            transient,
        }
    }

    pub fn is_transient(&self) -> bool {
        self.transient
    }
}

impl fmt::Display for LightningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} rail failed: {}", self.rail, self.detail)
    }
}

impl std::error::Error for LightningError {}

impl From<ClnError> for LightningError {
    fn from(error: ClnError) -> Self {
        Self::cln(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightningNodeInfo {
    pub block_height: u32,
    pub network: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightningInvoice {
    pub bolt11: String,
    pub payment_hash: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightningPayment {
    pub payment_hash: String,
    pub amount: Millisatoshi,
    pub amount_sent: Millisatoshi,
}

pub struct LightningPaymentPreimage([u8; 32]);

impl LightningPaymentPreimage {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn into_bytes(mut self) -> [u8; 32] {
        let bytes = self.0;
        self.0.fill(0);
        bytes
    }
}

impl From<ReleasedPaymentPreimage> for LightningPaymentPreimage {
    fn from(preimage: ReleasedPaymentPreimage) -> Self {
        Self::new(preimage.into_bytes())
    }
}

impl Drop for LightningPaymentPreimage {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for LightningPaymentPreimage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LightningPaymentPreimage([REDACTED])")
    }
}

pub struct LightningPreimage([u8; 32]);

impl LightningPreimage {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for LightningPreimage {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for LightningPreimage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LightningPreimage([REDACTED])")
    }
}

struct SensitiveText(Vec<u8>);

impl SensitiveText {
    fn lower_hex(bytes: &[u8]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = Vec::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize]);
            encoded.push(HEX[(byte & 0x0f) as usize]);
        }
        Self(encoded)
    }

    fn as_str(&self) -> Result<&str, LightningError> {
        std::str::from_utf8(&self.0).map_err(|_| LightningError {
            rail: "CLN",
            detail: "settlement preimage encoding failed".to_owned(),
            transient: false,
        })
    }
}

impl Drop for SensitiveText {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub trait LightningRail: fmt::Debug + Send + Sync {
    fn name(&self) -> &'static str;

    fn probe(&self, request_context: &str) -> LightningFuture<'_, ()>;

    fn node_info(&self, request_context: &str) -> LightningFuture<'_, LightningNodeInfo>;

    fn channel_capacity_sat(&self, request_context: &str) -> LightningFuture<'_, u64>;

    fn hold_invoice(
        &self,
        request_context: &str,
        payment_hash: &str,
        amount: Millisatoshi,
        expiry_seconds: u32,
        cltv_expiry: u32,
    ) -> LightningFuture<'_, LightningInvoice>;

    fn hold_invoice_state(
        &self,
        request_context: &str,
        payment_hash: &str,
    ) -> LightningFuture<'_, Value>;

    fn pay_with_released_preimage(
        &self,
        request_context: &str,
        bolt11: &str,
        maximum_fee: Millisatoshi,
    ) -> LightningFuture<'_, (LightningPayment, LightningPaymentPreimage)>;

    fn payment_settled_at(
        &self,
        request_context: &str,
        bolt11: &str,
        payment_hash: &str,
    ) -> LightningFuture<'_, u64>;

    fn settle_hold_invoice(
        &self,
        request_context: &str,
        preimage: LightningPreimage,
    ) -> LightningFuture<'_, ()>;

    fn cancel_hold_invoice(
        &self,
        request_context: &str,
        payment_hash: &str,
    ) -> LightningFuture<'_, ()>;
}

#[derive(Debug, Clone)]
pub struct ClnLightningRail {
    client: ClnClient,
    hold_policy: ClnHoldPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClnHoldPolicy {
    Stock,
    ImmortalRegtestExact,
}

impl ClnLightningRail {
    pub fn new(client: ClnClient) -> Self {
        Self {
            client,
            hold_policy: ClnHoldPolicy::Stock,
        }
    }

    pub fn with_immortal_regtest_policy(client: ClnClient) -> Self {
        Self {
            client,
            hold_policy: ClnHoldPolicy::ImmortalRegtestExact,
        }
    }

    fn request_id(request_context: &str) -> Result<ClnRequestId, LightningError> {
        ClnRequestId::new(request_context).map_err(LightningError::cln)
    }
}

impl LightningRail for ClnLightningRail {
    fn name(&self) -> &'static str {
        "cln"
    }

    fn probe(&self, request_context: &str) -> LightningFuture<'_, ()> {
        let request_context = request_context.to_owned();
        Box::pin(async move {
            self.client
                .probe_required_capabilities(&request_context)
                .await
                .map_err(LightningError::cln)?;
            if self.hold_policy == ClnHoldPolicy::ImmortalRegtestExact {
                self.client
                    .probe_capability(&request_context, IMMORTAL_REGTEST_HOLD_METHOD)
                    .await
                    .map_err(LightningError::cln)?;
            }
            Ok(())
        })
    }

    fn node_info(&self, request_context: &str) -> LightningFuture<'_, LightningNodeInfo> {
        let request_id = Self::request_id(request_context);
        Box::pin(async move {
            let info = self
                .client
                .node_info(&request_id?)
                .await
                .map_err(LightningError::cln)?;
            Ok(LightningNodeInfo {
                block_height: info.block_height,
                network: if info.network == "bitcoin" {
                    "mainnet".to_owned()
                } else {
                    info.network
                },
            })
        })
    }

    fn channel_capacity_sat(&self, request_context: &str) -> LightningFuture<'_, u64> {
        let request_id = Self::request_id(request_context);
        Box::pin(async move {
            let response = self
                .client
                .call(&request_id?, "listfunds", json!({}))
                .await
                .map_err(LightningError::cln)?;
            response
                .get("channels")
                .and_then(Value::as_array)
                .ok_or(ClnError::Json("listfunds returned no channel set"))?
                .iter()
                .filter(|channel| channel.get("connected").and_then(Value::as_bool) == Some(true))
                .try_fold(0_u64, |total, channel| {
                    let value = channel
                        .get("spendable_msat")
                        .or_else(|| channel.get("our_amount_msat"))
                        .ok_or(ClnError::Json("channel has no spendable amount"))?;
                    let amount = Millisatoshi::parse(value)?.to_satoshis_exact()?;
                    total.checked_add(amount).ok_or(ClnError::AmountOverflow)
                })
                .map_err(LightningError::cln)
        })
    }

    fn hold_invoice(
        &self,
        request_context: &str,
        payment_hash: &str,
        amount: Millisatoshi,
        expiry_seconds: u32,
        cltv_expiry: u32,
    ) -> LightningFuture<'_, LightningInvoice> {
        let request_id = Self::request_id(request_context);
        let payment_hash = payment_hash.to_owned();
        Box::pin(async move {
            let request_id = request_id?;
            let invoice = match self.hold_policy {
                ClnHoldPolicy::Stock => {
                    self.client
                        .hold_invoice(&request_id, &payment_hash, amount)
                        .await
                }
                ClnHoldPolicy::ImmortalRegtestExact => {
                    self.client
                        .immortal_regtest_hold_invoice(
                            &request_id,
                            &payment_hash,
                            amount,
                            expiry_seconds,
                            cltv_expiry,
                        )
                        .await
                }
            };
            invoice.map(Into::into).map_err(LightningError::cln)
        })
    }

    fn hold_invoice_state(
        &self,
        request_context: &str,
        payment_hash: &str,
    ) -> LightningFuture<'_, Value> {
        let request_id = Self::request_id(request_context);
        let payment_hash = payment_hash.to_owned();
        Box::pin(async move {
            self.client
                .list_hold_invoices(&request_id?, Some(&payment_hash))
                .await
                .map_err(LightningError::cln)
        })
    }

    fn pay_with_released_preimage(
        &self,
        request_context: &str,
        bolt11: &str,
        maximum_fee: Millisatoshi,
    ) -> LightningFuture<'_, (LightningPayment, LightningPaymentPreimage)> {
        let request_id = Self::request_id(request_context);
        let bolt11 = bolt11.to_owned();
        Box::pin(async move {
            let (payment, preimage) = self
                .client
                .pay_with_released_preimage(&request_id?, &bolt11, Some(maximum_fee))
                .await
                .map_err(LightningError::cln)?;
            Ok((payment.into(), preimage.into()))
        })
    }

    fn payment_settled_at(
        &self,
        request_context: &str,
        bolt11: &str,
        payment_hash: &str,
    ) -> LightningFuture<'_, u64> {
        let request_id = Self::request_id(request_context);
        let bolt11 = bolt11.to_owned();
        let payment_hash = payment_hash.to_owned();
        Box::pin(async move {
            let response = self
                .client
                .list_pays(&request_id?, Some(&bolt11))
                .await
                .map_err(LightningError::cln)?;
            response
                .get("pays")
                .and_then(Value::as_array)
                .and_then(|pays| {
                    pays.iter().find(|pay| {
                        pay.get("payment_hash").and_then(Value::as_str)
                            == Some(payment_hash.as_str())
                            && pay.get("status").and_then(Value::as_str) == Some("complete")
                    })
                })
                .and_then(|pay| pay.get("completed_at"))
                .and_then(Value::as_u64)
                .filter(|settled_at| *settled_at > 0)
                .ok_or_else(|| LightningError {
                    rail: "CLN",
                    detail: "completed payment has no stable settlement time".to_owned(),
                    transient: false,
                })
        })
    }

    fn settle_hold_invoice(
        &self,
        request_context: &str,
        preimage: LightningPreimage,
    ) -> LightningFuture<'_, ()> {
        let request_id = Self::request_id(request_context);
        let preimage = SensitiveText::lower_hex(preimage.as_bytes());
        Box::pin(async move {
            self.client
                .settle_hold_invoice(&request_id?, preimage.as_str()?)
                .await
                .map(|_| ())
                .map_err(LightningError::cln)
        })
    }

    fn cancel_hold_invoice(
        &self,
        request_context: &str,
        payment_hash: &str,
    ) -> LightningFuture<'_, ()> {
        let request_id = Self::request_id(request_context);
        let payment_hash = payment_hash.to_owned();
        Box::pin(async move {
            self.client
                .cancel_hold_invoice(&request_id?, &payment_hash)
                .await
                .map(|_| ())
                .map_err(LightningError::cln)
        })
    }
}

impl From<InvoiceResult> for LightningInvoice {
    fn from(invoice: InvoiceResult) -> Self {
        Self {
            bolt11: invoice.bolt11,
            payment_hash: invoice.payment_hash,
            expires_at: invoice.expires_at,
        }
    }
}

impl From<PaymentResult> for LightningPayment {
    fn from(payment: PaymentResult) -> Self {
        Self {
            payment_hash: payment.payment_hash,
            amount: payment.amount,
            amount_sent: payment.amount_sent,
        }
    }
}

#[cfg(feature = "lnd")]
#[derive(Debug, Clone)]
pub struct LndLightningRail {
    client: crate::lnd::LndClient,
}

#[cfg(feature = "lnd")]
impl LndLightningRail {
    pub fn new(client: crate::lnd::LndClient) -> Self {
        Self { client }
    }
}

#[cfg(feature = "lnd")]
impl LightningRail for LndLightningRail {
    fn name(&self) -> &'static str {
        "lnd"
    }

    fn probe(&self, _request_context: &str) -> LightningFuture<'_, ()> {
        Box::pin(async move {
            self.client
                .node_info()
                .await
                .map(|_| ())
                .map_err(LightningError::lnd)?;
            self.client
                .block_epoch()
                .await
                .map(|_| ())
                .map_err(LightningError::lnd)
        })
    }

    fn node_info(&self, _request_context: &str) -> LightningFuture<'_, LightningNodeInfo> {
        Box::pin(async move {
            let info = self.client.node_info().await.map_err(LightningError::lnd)?;
            Ok(LightningNodeInfo {
                block_height: info.block_height,
                network: info.network,
            })
        })
    }

    fn channel_capacity_sat(&self, _request_context: &str) -> LightningFuture<'_, u64> {
        Box::pin(async move {
            self.client
                .channel_capacity()
                .await
                .map_err(LightningError::lnd)?
                .to_satoshis_exact()
                .map_err(LightningError::cln)
        })
    }

    fn hold_invoice(
        &self,
        _request_context: &str,
        payment_hash: &str,
        amount: Millisatoshi,
        expiry_seconds: u32,
        cltv_expiry: u32,
    ) -> LightningFuture<'_, LightningInvoice> {
        let payment_hash = payment_hash.to_owned();
        Box::pin(async move {
            let invoice = self
                .client
                .hold_invoice(&payment_hash, amount, expiry_seconds, cltv_expiry)
                .await
                .map_err(LightningError::lnd)?;
            Ok(LightningInvoice {
                bolt11: invoice.bolt11,
                payment_hash: invoice.payment_hash,
                expires_at: invoice.expires_at,
            })
        })
    }

    fn hold_invoice_state(
        &self,
        _request_context: &str,
        payment_hash: &str,
    ) -> LightningFuture<'_, Value> {
        let payment_hash = payment_hash.to_owned();
        Box::pin(async move {
            self.client
                .normalized_hold_invoice(&payment_hash)
                .await
                .map_err(LightningError::lnd)
        })
    }

    fn pay_with_released_preimage(
        &self,
        _request_context: &str,
        bolt11: &str,
        maximum_fee: Millisatoshi,
    ) -> LightningFuture<'_, (LightningPayment, LightningPaymentPreimage)> {
        let bolt11 = bolt11.to_owned();
        Box::pin(async move {
            let invoice = immortal_core::mkt_swp_verify::parse_bolt11(&bolt11).map_err(|_| {
                LightningError::lnd(crate::lnd::LndError::InvalidConfiguration(
                    "BOLT11 is invalid",
                ))
            })?;
            let payment_hash = invoice
                .payment_hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let payment = match self.client.send_payment(&bolt11, maximum_fee, 60).await {
                Ok(payment) => payment,
                Err(crate::lnd::LndError::HttpStatus(409) | crate::lnd::LndError::Rpc(6)) => self
                    .client
                    .track_payment(&payment_hash)
                    .await
                    .map_err(LightningError::lnd)?,
                Err(error) => return Err(LightningError::lnd(error)),
            };
            if invoice.amount_msat != Some(payment.amount.as_millisatoshis()) {
                return Err(LightningError::lnd(crate::lnd::LndError::Json(
                    "payment response does not bind the requested invoice",
                )));
            }
            let preimage = payment.released_preimage.ok_or_else(|| LightningError {
                rail: "LND",
                detail: "completed payment released no preimage".to_owned(),
                transient: false,
            })?;
            Ok((
                LightningPayment {
                    payment_hash: payment.payment_hash,
                    amount: payment.amount,
                    amount_sent: payment.amount_sent,
                },
                LightningPaymentPreimage::new(preimage.into_bytes()),
            ))
        })
    }

    fn payment_settled_at(
        &self,
        _request_context: &str,
        _bolt11: &str,
        payment_hash: &str,
    ) -> LightningFuture<'_, u64> {
        let payment_hash = payment_hash.to_owned();
        Box::pin(async move {
            self.client
                .track_payment(&payment_hash)
                .await
                .map_err(LightningError::lnd)?
                .settled_at
                .ok_or_else(|| LightningError {
                    rail: "LND",
                    detail: "completed payment has no stable settlement time".to_owned(),
                    transient: false,
                })
        })
    }

    fn settle_hold_invoice(
        &self,
        _request_context: &str,
        preimage: LightningPreimage,
    ) -> LightningFuture<'_, ()> {
        Box::pin(async move {
            self.client
                .settle_hold_invoice(preimage.as_bytes())
                .await
                .map_err(LightningError::lnd)
        })
    }

    fn cancel_hold_invoice(
        &self,
        _request_context: &str,
        payment_hash: &str,
    ) -> LightningFuture<'_, ()> {
        let payment_hash = payment_hash.to_owned();
        Box::pin(async move {
            self.client
                .cancel_hold_invoice(&payment_hash)
                .await
                .map_err(LightningError::lnd)
        })
    }
}
