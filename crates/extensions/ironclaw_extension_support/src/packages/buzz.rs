//! Buzz extension package — Nostr-based messaging tool for Buzz channels.
//! WASM executor using host-mediated Nostr primitives (sign, publish, subscribe).

use std::borrow::Cow;

use super::{PackageBundle, PackageOnboarding, bytes_asset};

pub(super) const ID: &str = "buzz";

const MANIFEST: &str = include_str!("../../../packages/buzz/manifest.toml");
const WASM: &[u8] = include_bytes!("../../../packages/buzz/wasm/buzz_tool.component.wasm");

pub(super) fn bundle() -> PackageBundle {
    PackageBundle {
        id: ID,
        display_name: "Buzz",
        manifest_toml: Cow::Borrowed(MANIFEST),
        assets: vec![
            bytes_asset("manifest.toml", MANIFEST.as_bytes()),
            bytes_asset(
                "schemas/buzz.input.v1.json",
                include_bytes!("../../../packages/buzz/schemas/buzz.input.v1.json"),
            ),
            bytes_asset(
                "schemas/buzz.output.v1.json",
                include_bytes!("../../../packages/buzz/schemas/buzz.output.v1.json"),
            ),
            bytes_asset(
                "prompts/buzz.description.v1.md",
                include_bytes!("../../../packages/buzz/prompts/buzz.description.v1.md"),
            ),
            bytes_asset("wasm/buzz_tool.component.wasm", WASM),
        ],
        onboarding: Some(PackageOnboarding {
            instructions: "Buzz needs a Nostr private key (nsec or hex) to sign \
                and publish messages. Store it in the IronClaw secret store \
                under the handle \"wasm_nostr_private_key\" in the tenant-shared \
                managed scope."
                .to_string(),
            credential_instructions: Some(
                "Provide your Nostr private key (nsec or hex).".to_string(),
            ),
            setup_url: None,
            credential_next_step: "After saving the key, Buzz tools become available."
                .to_string(),
        }),
        // WASM tool package: trust comes from the extension registry.
        trust_effects: None,
    }
}
