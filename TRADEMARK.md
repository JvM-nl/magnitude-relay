# Vector Privacy Trademark Policy

Magnitude Relay is free and open-source software, released under the [GNU Affero General Public License, version 3](LICENSE) (AGPL-3.0-only). That license gives you broad rights to use, study, modify, and redistribute the source code. It does not, and cannot, grant rights to the Vector Privacy or Magnitude names, logos, or brand identity.

This document explains the difference, and sets out how you may and may not use those brands. It is written to be permissive. The goal is not to restrict the community, it is to make sure that when someone sees the Magnitude or Vector name on a relay, they know where the software actually came from.

***

## The Marks

The following are trademarks of Formless Labs, whether registered or unregistered:

- **Vector**, as the name of the messenger and the project
- **Vector Privacy**
- **Vector Messenger**
- The Vector logo and wordmark
- **Magnitude**, as the name of Vector's media server and relay
- **Magnitude Relay**
- **Concord** and **Concord Protocol**
- **Vector Hub**
- **Vector SDK**
- The Vector visual identity, including its color palette, iconography, and interface design language

These are referred to below as the "Marks."

***

## What This Policy Does Not Do

This policy places **no restrictions whatsoever** on the source code beyond those of the AGPL itself. You may:

- Fork the repository
- Modify the source however you like
- Build and run your own relay, public or private
- Distribute your build, including commercially
- Study, audit, and publish findings about the code

Nothing in this document limits any right the AGPL grants you over the code itself, and nothing in it adds to the AGPL's conditions. Trademark and copyright are separate bodies of law, and this policy concerns only the former.

***

## Uses That Need No Permission

You do not need to ask us for any of the following:

**Referring to Magnitude Relay or Vector.** Naming them in articles, reviews, tutorials, comparisons, benchmarks, academic papers, talks, and social media posts. This includes critical coverage. We would rather you write honestly about them than write about them with our approval.

**Saying what your relay runs.** Stating truthfully that your relay runs Magnitude Relay ("powered by Magnitude Relay"), as long as it runs an official, unmodified release.

**Describing compatibility.** Stating truthfully that your software or relay works with Vector. "A relay tested with Vector," "Concord-compatible," and similar phrasing are all fine.

**Unmodified redistribution.** Distributing official, unmodified Magnitude Relay builds under its name, including mirroring releases or packaging them for a distribution's repositories.

**Linking.** Using the Vector logo as a link back to an official Vector site or repository.

**Fair use.** Anything that qualifies as nominative or descriptive fair use under applicable law, which generally covers the cases above and more.

***

## Uses That Need Permission

Please ask before doing any of the following:

**Leading with the mark.** Naming your project or relay so that a Mark comes first or dominates. "Magnitude EU" or "Vector Relay Asia" reads like an official Vector service. "Kiwi Relay, powered by Magnitude Relay" does not. Use the second shape.

**Shipping modified builds under the Magnitude name.** If you have changed the code, the build is no longer Magnitude Relay. Give it your own name. See [Forks](#forks) below.

**Using the logo as your own identity.** The Vector logo should not appear as the icon, avatar, or primary branding of your relay, project, service, or organization.

**Merchandise.** Producing physical or digital goods bearing the Marks for sale.

**Domain names and account handles.** Registering domains, social accounts, or package names that lead with a Mark in a way that suggests an official channel.

**Implying endorsement.** Describing a relay or anything else as "official," "certified," "approved," "partnered," or "verified" in relation to Vector or Magnitude without a written agreement from us.

***

## Forks

Forking is explicitly welcome. It is one of the reasons the source is open.

If you publish a fork, or run a modified relay for others, please:

1. **Give it a different name.** Not one that a reasonable person would mistake for Magnitude Relay or a Vector service, and not one that simply appends a word to "Magnitude" or "Vector." The name lives in [`crates/relay-server/src/brand.rs`](crates/relay-server/src/brand.rs) and the `[[bin]]` name in `Cargo.toml`.
2. **Use your own logo and branding.** Replace the Vector mark, wordmark and look of the relay's built-in pages (`crates/relay-server/src/web/`), and your release assets.
3. **State the relationship honestly.** Something like "based on Magnitude Relay" in your README is accurate, useful to your users, and entirely permitted.
4. **Do not use our infrastructure branding.** Do not present your relay as one of Vector's relays, or use Vector's domains, support channels, or release channels as though they were yours.
5. **Share your changes as the AGPL requires.** That is the license, not this policy, but it is the part forks most often miss: if people use your modified relay over the network, offer them its source.

We ask this for a practical reason: if a fork ships a security regression, or a malicious build circulates under our name, users have no way to tell the difference. A relay carries people's encrypted messages; distinct names protect them and you as much as us.

***

## Attribution

If you use the Marks under this policy, a short attribution is appreciated but not required:

> Vector Privacy, Magnitude Relay and the Vector logo are trademarks of Formless Labs.

***

## Enforcement

Our first step is always a conversation. If we think a use is confusing, we will contact you and explain why, and in most cases a small change to a name or an icon resolves it. We are not interested in sending legal threats to people building useful things.

We reserve the right to enforce these Marks where a use genuinely misleads users about the origin of software, particularly where security or user safety is at stake. Running or distributing modified or malicious builds under the Magnitude or Vector Privacy name is the case we care about, and the case this policy exists to address.

***

## Changes to This Policy

This policy may be updated as the project grows. Changes will be published in this file, and its history is visible in the repository.

***

## Questions

If you are unsure whether your use is permitted, please ask before you launch. It is far easier to adjust a name before release than after.

Contact: `info@vectorapp.io`

***

*Vector Privacy, Magnitude Relay and the Vector logo are trademarks of Formless Labs. All other trademarks are the property of their respective owners.*

*Last updated: October 2026*
