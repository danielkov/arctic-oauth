mod client;
mod error;
mod http;
mod oidc;
mod pkce;
mod providers;
mod request;
mod state;
mod tokens;

// Core
pub use client::OAuth2Client;
pub use error::Error;
pub use http::{HttpClient, HttpRequest, HttpResponse};
pub use tokens::OAuth2Tokens;

// Utilities
pub use oidc::decode_id_token;
pub use pkce::{CodeChallengeMethod, create_code_challenge, generate_code_verifier};
pub use state::generate_state;

// Default HTTP client (behind feature flag)
#[cfg(feature = "reqwest-client")]
pub use http::ReqwestClient;

// Providers (each behind its own feature flag)
#[cfg(feature = "discord")]
pub use providers::discord::Discord;
#[cfg(feature = "github")]
pub use providers::github::GitHub;
#[cfg(feature = "google")]
pub use providers::google::Google;

#[cfg(feature = "forty-two")]
pub use providers::forty_two::FortyTwo;
#[cfg(feature = "amazon-cognito")]
pub use providers::amazon_cognito::AmazonCognito;
#[cfg(feature = "anilist")]
pub use providers::anilist::AniList;
#[cfg(feature = "apple")]
pub use providers::apple::Apple;
#[cfg(feature = "atlassian")]
pub use providers::atlassian::Atlassian;
#[cfg(feature = "auth0")]
pub use providers::auth0::Auth0;
#[cfg(feature = "authentik")]
pub use providers::authentik::Authentik;
#[cfg(feature = "autodesk")]
pub use providers::autodesk::Autodesk;
#[cfg(feature = "battle-net")]
pub use providers::battle_net::BattleNet;
#[cfg(feature = "bitbucket")]
pub use providers::bitbucket::Bitbucket;
#[cfg(feature = "box-oauth")]
pub use providers::box_oauth::BoxOAuth;
#[cfg(feature = "bungie")]
pub use providers::bungie::Bungie;
#[cfg(feature = "coinbase")]
pub use providers::coinbase::Coinbase;
#[cfg(feature = "donation-alerts")]
pub use providers::donation_alerts::DonationAlerts;
#[cfg(feature = "dribbble")]
pub use providers::dribbble::Dribbble;
#[cfg(feature = "dropbox")]
pub use providers::dropbox::Dropbox;
#[cfg(feature = "epic-games")]
pub use providers::epic_games::EpicGames;
#[cfg(feature = "etsy")]
pub use providers::etsy::Etsy;
#[cfg(feature = "facebook")]
pub use providers::facebook::Facebook;
#[cfg(feature = "figma")]
pub use providers::figma::Figma;
#[cfg(feature = "gitea")]
pub use providers::gitea::Gitea;
#[cfg(feature = "gitlab")]
pub use providers::gitlab::GitLab;
#[cfg(feature = "intuit")]
pub use providers::intuit::Intuit;
#[cfg(feature = "kakao")]
pub use providers::kakao::Kakao;
#[cfg(feature = "keycloak")]
pub use providers::keycloak::KeyCloak;
#[cfg(feature = "kick")]
pub use providers::kick::Kick;
#[cfg(feature = "lichess")]
pub use providers::lichess::Lichess;
#[cfg(feature = "line")]
pub use providers::line::Line;
#[cfg(feature = "linear")]
pub use providers::linear::Linear;
#[cfg(feature = "linkedin")]
pub use providers::linkedin::LinkedIn;
#[cfg(feature = "mastodon")]
pub use providers::mastodon::Mastodon;
#[cfg(feature = "mercado-libre")]
pub use providers::mercado_libre::MercadoLibre;
#[cfg(feature = "mercado-pago")]
pub use providers::mercado_pago::MercadoPago;
#[cfg(feature = "microsoft-entra-id")]
pub use providers::microsoft_entra_id::MicrosoftEntraId;
#[cfg(feature = "my-anime-list")]
pub use providers::my_anime_list::MyAnimeList;
#[cfg(feature = "naver")]
pub use providers::naver::Naver;
#[cfg(feature = "notion")]
pub use providers::notion::Notion;
#[cfg(feature = "okta")]
pub use providers::okta::Okta;
#[cfg(feature = "osu")]
pub use providers::osu::Osu;
#[cfg(feature = "patreon")]
pub use providers::patreon::Patreon;
#[cfg(feature = "polar")]
pub use providers::polar::Polar;
#[cfg(feature = "reddit")]
pub use providers::reddit::Reddit;
#[cfg(feature = "roblox")]
pub use providers::roblox::Roblox;
#[cfg(feature = "salesforce")]
pub use providers::salesforce::Salesforce;
#[cfg(feature = "shikimori")]
pub use providers::shikimori::Shikimori;
#[cfg(feature = "slack")]
pub use providers::slack::Slack;
#[cfg(feature = "spotify")]
pub use providers::spotify::Spotify;
#[cfg(feature = "start-gg")]
pub use providers::start_gg::StartGG;
#[cfg(feature = "strava")]
pub use providers::strava::Strava;
#[cfg(feature = "synology")]
pub use providers::synology::Synology;
#[cfg(feature = "tiktok")]
pub use providers::tiktok::TikTok;
#[cfg(feature = "tiltify")]
pub use providers::tiltify::Tiltify;
#[cfg(feature = "tumblr")]
pub use providers::tumblr::Tumblr;
#[cfg(feature = "twitch")]
pub use providers::twitch::Twitch;
#[cfg(feature = "twitter")]
pub use providers::twitter::Twitter;
#[cfg(feature = "vk")]
pub use providers::vk::VK;
#[cfg(feature = "withings")]
pub use providers::withings::Withings;
#[cfg(feature = "workos")]
pub use providers::workos::WorkOS;
#[cfg(feature = "yahoo")]
pub use providers::yahoo::Yahoo;
#[cfg(feature = "yandex")]
pub use providers::yandex::Yandex;
#[cfg(feature = "zoom")]
pub use providers::zoom::Zoom;
