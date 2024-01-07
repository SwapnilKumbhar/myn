use std::ffi::CString;

use crate::strategies::{AuthenticationError, Strategy};
use log::{error, info};
use pam_client::{Context, ConversationHandler, ErrorCode};

#[derive(Debug)]
pub struct Pam {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct PamAuthData {
    pub username: String,
    pub password: String,
}

impl ConversationHandler for PamAuthData {
    fn prompt_echo_on(
        &mut self,
        prompt: &std::ffi::CStr,
    ) -> Result<std::ffi::CString, pam_client::ErrorCode> {
        info!("Prompt echo on: {}", prompt.to_string_lossy());
        Ok(CString::new(self.password.clone()).unwrap())
    }

    fn prompt_echo_off(
        &mut self,
        prompt: &std::ffi::CStr,
    ) -> Result<std::ffi::CString, pam_client::ErrorCode> {
        info!("Prompt echo off: {}", prompt.to_string_lossy());
        Ok(CString::new(self.password.clone()).unwrap())
    }

    fn text_info(&mut self, msg: &std::ffi::CStr) {
        info!("Conv text Info: {}", msg.to_string_lossy());
    }

    fn error_msg(&mut self, msg: &std::ffi::CStr) {
        error!("Conv error: {}", msg.to_string_lossy());
    }
}

impl Strategy<PamAuthData> for Pam {
    fn authenticate(&self, auth_data: PamAuthData) -> Result<(), AuthenticationError> {
        info!("Authenticating user: {}", auth_data.username);
        let mut pam_ctx = match Context::new(
            "login",
            Some(auth_data.username.as_str()),
            auth_data.clone(),
        ) {
            Ok(ctx) => ctx,
            Err(_) => return Err(AuthenticationError::StrategyInitFailed),
        };

        let result = pam_ctx.authenticate(pam_client::Flag::DISALLOW_NULL_AUTHTOK);
        match result {
            Ok(_) => info!("Succeeded auth"),
            Err(e) => {
                error!(
                    "Failed authentication of {} with error: {}",
                    auth_data.username, e
                );
                match e.code() {
                    ErrorCode::ABORT => return Err(AuthenticationError::AuthenticationFailed),
                    ErrorCode::AUTH_ERR => return Err(AuthenticationError::AuthenticationFailed),

                    _ => return Err(AuthenticationError::AuthenticationFailed),
                }
            }
        };

        Ok(())
    }
    fn get_name(&self) -> String {
        self.name.clone()
    }
    fn get_description(&self) -> std::string::String {
        self.description.clone()
    }
}
