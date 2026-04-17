# Extend OAuth login for phpBB

![Example of login](docs/assets/example.png)

The intention of this extension is to extend the list of Phpbb OAuth providers.
At the moment it adds **Github, Discord, Microsoft, Reddit, SUPLA and Wordpress** as oauth providers.

This is a public version of my private plugin `dsr/oauth_register` that I developed for use in Indetectables.net.

If you are interested in acquiring the private version with registration flow, you can do it from [here](https://xchwarze.github.io/).

## Requirements

- phpBB >= 3.3.0
- PHP extension CURL
- HTTPS enabled and capable site.

## Installation

1. Copy the extension to the `/ext/dsr/oauthlogin`.
2. Access the ACP (Admin Control Panel) of your phpBB installation.
3. Navigate to `Customise -> Extensions`.
4. Enable the **Extended OAuth Login** extension.

## OAuth providers

You can find a detailed explanation on how to configure the providers in [this file](providers.md).

## CLI smoke test

The repository includes a standalone CLI smoke test for SUPLA OAuth:

```bash
php tools/supla_oauth_smoke.php --client-id=... --client-secret=...
```

It prints the authorization URL, lets you complete the SUPLA login/consent flow in a browser, and then exchanges the callback code for a token before calling `/users/current`.

To force a specific SUPLA server for tests, use:

```bash
php tools/supla_oauth_smoke.php --client-id=... --client-secret=... --server-host=svr23.supla.org
```

## License

[GPLv2](license.txt)
