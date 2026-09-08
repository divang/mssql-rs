// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows-only inbound NTLM authentication using SSPI.

#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::c_void;
use std::ptr;
use thiserror::Error;

type SECURITY_STATUS = i32;
type ULONG = u32;
type PVOID = *mut c_void;

const SEC_E_OK: SECURITY_STATUS = 0;
const SEC_I_CONTINUE_NEEDED: SECURITY_STATUS = 0x0009_0312;
const SEC_I_COMPLETE_NEEDED: SECURITY_STATUS = 0x0009_0313;
const SEC_I_COMPLETE_AND_CONTINUE: SECURITY_STATUS = 0x0009_0314;
const SECPKG_CRED_INBOUND: ULONG = 1;
const ASC_REQ_CONNECTION: ULONG = 0x0000_0800;
const SECURITY_NATIVE_DREP: ULONG = 0x0000_0010;
const SECBUFFER_VERSION: ULONG = 0;
const SECBUFFER_TOKEN: ULONG = 2;
const SECPKG_ATTR_NAMES: ULONG = 1;

#[repr(C)]
#[derive(Default)]
struct SecHandle {
    dwLower: usize,
    dwUpper: usize,
}

impl SecHandle {
    fn is_valid(&self) -> bool {
        self.dwLower != 0 || self.dwUpper != 0
    }
}

#[repr(C)]
#[derive(Default)]
struct TimeStamp {
    LowPart: u32,
    HighPart: i32,
}

#[repr(C)]
struct SecBuffer {
    cbBuffer: ULONG,
    BufferType: ULONG,
    pvBuffer: PVOID,
}

#[repr(C)]
struct SecBufferDesc {
    ulVersion: ULONG,
    cBuffers: ULONG,
    pBuffers: *mut SecBuffer,
}

#[repr(C)]
struct SecPkgContextNamesW {
    sUserName: *mut u16,
}

#[link(name = "secur32")]
unsafe extern "system" {
    fn AcquireCredentialsHandleW(
        pszPrincipal: *const u16,
        pszPackage: *const u16,
        fCredentialUse: ULONG,
        pvLogonId: PVOID,
        pAuthData: PVOID,
        pGetKeyFn: PVOID,
        pvGetKeyArgument: PVOID,
        phCredential: *mut SecHandle,
        ptsExpiry: *mut TimeStamp,
    ) -> SECURITY_STATUS;

    fn AcceptSecurityContext(
        phCredential: *const SecHandle,
        phContext: *const SecHandle,
        pInput: *const SecBufferDesc,
        fContextReq: ULONG,
        TargetDataRep: ULONG,
        phNewContext: *mut SecHandle,
        pOutput: *mut SecBufferDesc,
        pfContextAttr: *mut ULONG,
        ptsExpiry: *mut TimeStamp,
    ) -> SECURITY_STATUS;

    fn CompleteAuthToken(
        phContext: *const SecHandle,
        pToken: *const SecBufferDesc,
    ) -> SECURITY_STATUS;
    fn QueryContextAttributesW(
        phContext: *const SecHandle,
        ulAttribute: ULONG,
        pBuffer: PVOID,
    ) -> SECURITY_STATUS;
    fn FreeContextBuffer(pvContextBuffer: PVOID) -> SECURITY_STATUS;
    fn DeleteSecurityContext(phContext: *mut SecHandle) -> SECURITY_STATUS;
    fn FreeCredentialsHandle(phCredential: *mut SecHandle) -> SECURITY_STATUS;
}

#[derive(Debug, Error)]
pub enum SspiError {
    #[error("unable to acquire inbound NTLM credentials (status 0x{0:08X})")]
    Acquire(u32),
    #[error("NTLM authentication failed (status 0x{0:08X})")]
    Accept(u32),
    #[error("unable to complete NTLM token (status 0x{0:08X})")]
    Complete(u32),
    #[error("unable to query authenticated identity (status 0x{0:08X})")]
    Identity(u32),
    #[error("SSPI returned an invalid output token")]
    InvalidOutput,
    #[error("SSPI token exceeds the configured limit")]
    TokenTooLarge,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AcceptResult {
    Continue(Vec<u8>),
    Complete {
        identity: String,
        final_token: Vec<u8>,
    },
}

/// One inbound NTLM authentication conversation.
pub struct WindowsNtlmAcceptor {
    credential: SecHandle,
    context: SecHandle,
    has_context: bool,
    max_token_size: usize,
}

// A conversation is owned by one connection task and never used concurrently.
unsafe impl Send for WindowsNtlmAcceptor {}

impl WindowsNtlmAcceptor {
    pub fn new(max_token_size: usize) -> Result<Self, SspiError> {
        let package: Vec<u16> = "NTLM".encode_utf16().chain(std::iter::once(0)).collect();
        let mut credential = SecHandle::default();
        let mut expiry = TimeStamp::default();
        // SAFETY: all pointers reference initialized storage for the duration of the call.
        let status = unsafe {
            AcquireCredentialsHandleW(
                ptr::null(),
                package.as_ptr(),
                SECPKG_CRED_INBOUND,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut credential,
                &mut expiry,
            )
        };
        if status != SEC_E_OK {
            return Err(SspiError::Acquire(status as u32));
        }

        Ok(Self {
            credential,
            context: SecHandle::default(),
            has_context: false,
            max_token_size,
        })
    }

    pub fn accept(&mut self, token: &[u8]) -> Result<AcceptResult, SspiError> {
        if token.len() > self.max_token_size {
            return Err(SspiError::TokenTooLarge);
        }

        let mut input = token.to_vec();
        let mut input_buffer = SecBuffer {
            cbBuffer: input.len() as ULONG,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: input.as_mut_ptr().cast(),
        };
        let input_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut input_buffer,
        };

        let mut output = vec![0u8; self.max_token_size];
        let mut output_buffer = SecBuffer {
            cbBuffer: output.len() as ULONG,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: output.as_mut_ptr().cast(),
        };
        let mut output_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut output_buffer,
        };
        let mut new_context = SecHandle::default();
        let mut attributes = 0;
        let mut expiry = TimeStamp::default();
        let prior_context = if self.has_context {
            &self.context as *const SecHandle
        } else {
            ptr::null()
        };

        // SAFETY: descriptors and backing buffers remain alive and writable during the call.
        let status = unsafe {
            AcceptSecurityContext(
                &self.credential,
                prior_context,
                &input_desc,
                ASC_REQ_CONNECTION,
                SECURITY_NATIVE_DREP,
                &mut new_context,
                &mut output_desc,
                &mut attributes,
                &mut expiry,
            )
        };

        if new_context.is_valid() {
            self.context = new_context;
            self.has_context = true;
        }
        if status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE {
            // SAFETY: SSPI created this context and output descriptor.
            let complete_status = unsafe { CompleteAuthToken(&self.context, &output_desc) };
            if complete_status != SEC_E_OK {
                return Err(SspiError::Complete(complete_status as u32));
            }
        }

        if output_buffer.cbBuffer as usize > output.len() {
            return Err(SspiError::InvalidOutput);
        }
        output.truncate(output_buffer.cbBuffer as usize);

        match status {
            SEC_I_CONTINUE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE => {
                Ok(AcceptResult::Continue(output))
            }
            SEC_E_OK | SEC_I_COMPLETE_NEEDED => Ok(AcceptResult::Complete {
                identity: self.identity()?,
                final_token: output,
            }),
            _ => Err(SspiError::Accept(status as u32)),
        }
    }

    fn identity(&self) -> Result<String, SspiError> {
        let mut names = SecPkgContextNamesW {
            sUserName: ptr::null_mut(),
        };
        // SAFETY: the context is complete and `names` is valid output storage.
        let status = unsafe {
            QueryContextAttributesW(
                &self.context,
                SECPKG_ATTR_NAMES,
                (&mut names as *mut SecPkgContextNamesW).cast(),
            )
        };
        if status != SEC_E_OK {
            return Err(SspiError::Identity(status as u32));
        }
        if names.sUserName.is_null() {
            return Err(SspiError::InvalidOutput);
        }

        // SAFETY: SSPI returns a null-terminated UTF-16 string for SECPKG_ATTR_NAMES.
        let identity = unsafe {
            let mut len = 0usize;
            while *names.sUserName.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(names.sUserName, len))
        };
        // SAFETY: SSPI allocated this buffer for the caller.
        unsafe {
            FreeContextBuffer(names.sUserName.cast());
        }
        Ok(identity)
    }
}

impl Drop for WindowsNtlmAcceptor {
    fn drop(&mut self) {
        // SAFETY: each valid SSPI handle is released exactly once here.
        unsafe {
            if self.has_context {
                DeleteSecurityContext(&mut self.context);
            }
            if self.credential.is_valid() {
                FreeCredentialsHandle(&mut self.credential);
            }
        }
    }
}
