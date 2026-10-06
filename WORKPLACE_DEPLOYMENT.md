# Avantis FireWall deployment

Avantis FireWall helps teams manage a local list of websites to restrict on a Windows PC. It includes editable domain lists, explainable site checks, bulk import, activity controls, and a password-protected Safe Mode.

## Before you deploy

- Review the starter website list and add or remove entries to match your organization's policy.
- Protection applies across browsers and Windows accounts on each PC where it is enabled.
- Applying or removing protection requires approval from a Windows administrator.
- The app checks the address entered by a user; it does not monitor successful browsing.
- A website served from a separate domain must be included as a separate rule.

## Installation

Build the Windows installer with the steps in [README.md](./README.md), then distribute the generated setup to authorized users. Each user reviews the Terms of Use and Privacy Notice on first launch. Rules and activity are stored locally for that Windows user.

Administrators should communicate the organization's acceptable-use policy and who is authorized to enable or remove website restrictions. Users with permission can review protection status and make changes from the app.

## Privacy

Avantis does not require an account. Manual checks, settings, and administrative actions are kept on the PC. Normal browsing is not monitored. Downloading a public list connects the PC to the list provider.
