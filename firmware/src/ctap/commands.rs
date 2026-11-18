//! Typed dispatch; CBOR decoding and transport framing are separate boundaries.

use super::{
    credential_management, credentials, pin_uv,
    status::{Result, Status},
};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
    CredentialManagement = 0x0a,
    Selection = 0x0b,
}

impl TryFrom<u8> for Command {
    type Error = Status;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::MakeCredential),
            0x02 => Ok(Self::GetAssertion),
            0x04 => Ok(Self::GetInfo),
            0x06 => Ok(Self::ClientPin),
            0x07 => Ok(Self::Reset),
            0x08 => Ok(Self::GetNextAssertion),
            0x0a => Ok(Self::CredentialManagement),
            0x0b => Ok(Self::Selection),
            _ => Err(Status::InvalidCommand),
        }
    }
}

pub enum Request<'a> {
    MakeCredential(credentials::MakeCredential<'a>),
    GetAssertion(credentials::GetAssertion<'a>),
    GetInfo,
    ClientPin(pin_uv::Request<'a>),
    Reset,
    GetNextAssertion,
    CredentialManagement(credential_management::Request<'a>),
    Selection,
}

/// Assigned by the transport owner, never taken from CBOR. Lets the backend
/// associate continuation state with its caller. Not an authorization grant.
#[derive(Clone, Copy)]
pub struct RequestContext {
    pub session_id: u32,
}

/// Implement with a single owner of repository, PIN/UV, presence, clock, RNG,
/// and operation state. Every method is required; there are no success stubs.
///
/// Methods validate requests in normative order, enforce policy, and encode only
/// the CBOR response body into output (no leading CTAP status). Reset/selection
/// return length zero on success, after their required user-presence flow.
/// getInfo must describe actual completed behavior, not the TARGET_* constants.
/// Async futures intentionally need not be Send: Embassy runs these locally.
#[allow(async_fn_in_trait)]
pub trait Handlers {
    async fn make_credential(
        &mut self,
        context: RequestContext,
        request: credentials::MakeCredential<'_>,
        output: &mut [u8],
    ) -> Result<usize>;
    async fn get_assertion(
        &mut self,
        context: RequestContext,
        request: credentials::GetAssertion<'_>,
        output: &mut [u8],
    ) -> Result<usize>;
    async fn get_info(&mut self, context: RequestContext, output: &mut [u8]) -> Result<usize>;
    async fn client_pin(
        &mut self,
        context: RequestContext,
        request: pin_uv::Request<'_>,
        output: &mut [u8],
    ) -> Result<usize>;
    async fn reset(&mut self, context: RequestContext) -> Result<()>;
    async fn get_next_assertion(
        &mut self,
        context: RequestContext,
        output: &mut [u8],
    ) -> Result<usize>;
    async fn credential_management(
        &mut self,
        context: RequestContext,
        request: credential_management::Request<'_>,
        output: &mut [u8],
    ) -> Result<usize>;
    async fn selection(&mut self, context: RequestContext) -> Result<()>;
}

/// Call only after bounded, canonical CBOR decoding. This routes typed inputs;
/// it does not confer authentication or implement command algorithms. Await
/// completion; cancellation belongs at safe points in the backend, not around
/// flash operations. On an error, the whole response buffer is cleared.
pub async fn execute(
    handlers: &mut impl Handlers,
    context: RequestContext,
    request: Request<'_>,
    output: &mut [u8],
) -> Result<usize> {
    output.zeroize();
    let result = match request {
        Request::MakeCredential(request) => {
            handlers.make_credential(context, request, output).await
        }
        Request::GetAssertion(request) => handlers.get_assertion(context, request, output).await,
        Request::GetInfo => handlers.get_info(context, output).await,
        Request::ClientPin(request) => handlers.client_pin(context, request, output).await,
        Request::Reset => handlers.reset(context).await.map(|()| 0),
        Request::GetNextAssertion => handlers.get_next_assertion(context, output).await,
        Request::CredentialManagement(request) => {
            handlers
                .credential_management(context, request, output)
                .await
        }
        Request::Selection => handlers.selection(context).await.map(|()| 0),
    };
    match result {
        Ok(len) if len <= output.len() => Ok(len),
        Ok(_) => {
            output.zeroize();
            Err(Status::Other)
        }
        Err(status) => {
            output.zeroize();
            Err(status)
        }
    }
}
