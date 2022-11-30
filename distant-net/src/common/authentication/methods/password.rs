use super::{AuthenticationMethod, Authenticator, Challenge, Error, Question};
use crate::map;
use async_trait::async_trait;
use std::io;

/// Authenticaton method for a username and password
#[derive(Clone, Debug)]
pub struct PasswordAuthenticationMethod {
    allowed_usernames: Option<Vec<String>>,
    denied_usernames: Option<Vec<String>>,
}

impl PasswordAuthenticationMethod {
    #[inline]
    pub fn new(
        allowed_usernames: impl Into<Option<Vec<String>>>,
        denied_usernames: impl Into<Option<Vec<String>>>,
    ) -> Self {
        Self {
            allowed_usernames: allowed_usernames.into(),
            denied_usernames: denied_usernames.into(),
        }
    }
}

#[async_trait]
impl AuthenticationMethod for PasswordAuthenticationMethod {
    fn id(&self) -> &'static str {
        "password"
    }

    async fn authenticate(&self, authenticator: &mut dyn Authenticator) -> io::Result<()> {
        let response = authenticator
            .challenge(Challenge {
                questions: vec![
                    Question {
                        label: "username".to_string(),
                        text: "Username: ".to_string(),
                        options: map!("echo" -> "true").into_map(),
                    },
                    Question {
                        label: "password".to_string(),
                        text: "Password: ".to_string(),
                        options: Default::default(),
                    },
                ],
                options: Default::default(),
            })
            .await?;

        if response.answers.is_empty() {
            return Err(Error::non_fatal("missing username").into_io_permission_denied());
        } else if response.answers.len() == 1 {
            return Err(Error::non_fatal("missing password").into_io_permission_denied());
        }

        let mut it = response.answers.into_iter().take(2);
        let username = it.next().unwrap();
        let password = it.next().unwrap();

        #[cfg(unix)]
        {
            use pam_client::conv_mock::Conversation;
            use pam_client::{Context, Flag};

            let mut context = Context::new(
                "distant", // Service name
                None,
                Conversation::with_credentials(username, password),
            )
            .expect("Failed to initialize PAM context");

            // Authenticate the user
            context
                .authenticate(Flag::NONE)
                .expect("Authentication failed");

            // Validate the account
            context
                .acct_mgmt(Flag::NONE)
                .expect("Account validation failed");

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        authentication::msg::{AuthenticationResponse, ChallengeResponse},
        FramedTransport,
    };
    use test_log::test;

    #[test(tokio::test)]
    async fn authenticate_should_fail_if_key_challenge_fails() {
        let method = StaticKeyAuthenticationMethod::new(b"".to_vec());
        let (mut t1, mut t2) = FramedTransport::test_pair(100);

        // Queue up an invalid frame for our challenge to ensure it fails
        t2.write_frame(b"invalid initialization response")
            .await
            .unwrap();

        assert_eq!(
            method.authenticate(&mut t1).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test(tokio::test)]
    async fn authenticate_should_fail_if_no_answer_included_in_challenge_response() {
        let method = StaticKeyAuthenticationMethod::new(b"".to_vec());
        let (mut t1, mut t2) = FramedTransport::test_pair(100);

        // Queue up a response to the initialization request
        t2.write_frame_for(&AuthenticationResponse::Challenge(ChallengeResponse {
            answers: Vec::new(),
        }))
        .await
        .unwrap();

        assert_eq!(
            method.authenticate(&mut t1).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test(tokio::test)]
    async fn authenticate_should_fail_if_answer_does_not_match_key() {
        let method = StaticKeyAuthenticationMethod::new(b"answer".to_vec());
        let (mut t1, mut t2) = FramedTransport::test_pair(100);

        // Queue up a response to the initialization request
        t2.write_frame_for(&AuthenticationResponse::Challenge(ChallengeResponse {
            answers: vec![HeapSecretKey::from(b"some key".to_vec()).to_string()],
        }))
        .await
        .unwrap();

        assert_eq!(
            method.authenticate(&mut t1).await.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test(tokio::test)]
    async fn authenticate_should_succeed_if_answer_matches_key() {
        let method = StaticKeyAuthenticationMethod::new(b"answer".to_vec());
        let (mut t1, mut t2) = FramedTransport::test_pair(100);

        // Queue up a response to the initialization request
        t2.write_frame_for(&AuthenticationResponse::Challenge(ChallengeResponse {
            answers: vec![HeapSecretKey::from(b"answer".to_vec()).to_string()],
        }))
        .await
        .unwrap();

        method.authenticate(&mut t1).await.unwrap();
    }
}
