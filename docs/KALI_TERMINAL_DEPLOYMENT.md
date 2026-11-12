# Kali terminal deployment for OpsAegis

The Kali terminal is hosted in a separate Railway project so it does not consume another service slot in the existing five-service OpsAegis project.

## Railway project

- Project: `OpsAegis-Kali-Terminal`
- Project ID: `313791b3-2048-4a41-9d0f-5590eaee75a5`
- Dashboard: https://railway.com/project/313791b3-2048-4a41-9d0f-5590eaee75a5
- Template: https://railway.com/deploy/kali-linux-web-terminal
- Template source: `decoge/kali-linux-webterminal-railway` (third-party, not Railway-verified)

The project has been created, but the template has **not** been deployed. Railway's deploy API cannot accept the template's required `USERNAME` and `PASSWORD` secrets. Deploy it from the Railway dashboard and enter those values there; never commit or paste them into GitHub, chat, or frontend variables.

## Deploy the template

1. Open the [Kali Linux Web Terminal template](https://railway.com/deploy/kali-linux-web-terminal) and choose the existing `OpsAegis-Kali-Terminal` project.
2. Review the third-party source repository before deploying; the template is not Railway-verified.
3. Enter a strong unique `USERNAME` and `PASSWORD` in Railway's variable form.
4. Confirm the template's persistent volume is mounted at `/data`.
5. After deployment succeeds, generate a Railway HTTPS domain for the Kali service (the template uses ttyd's web port; verify the service's exposed port in its settings/logs before assigning the domain).
6. Test the domain in a private browser window. It must prompt for HTTP Basic Authentication before showing a terminal.

The template provides a shared team Basic Auth login, not individual OpsAegis SSO identities. Share credentials only with approved operators and rotate them if a team member leaves. Do not add the credentials to OpsAegis.

## Connect the button in OpsAegis

Set this **non-secret URL only** on the OpsAegis `frontend` Railway service:

```text
VITE_KALI_TERMINAL_URL=https://<your-kali-service-domain>
```

Then redeploy the frontend. The Integrations page shows an **Open Kali web terminal** link for active administrators and analysts. It opens the HTTPS terminal in a new tab, where Railway template Basic Auth is enforced. No password or Basic Auth header is embedded in frontend code.

If the URL is not set, the panel shows a link to the separate Kali Railway project dashboard instead.

## Important security notes

- Never expose the terminal without Basic Auth. Do not remove the template's authentication.
- Use the terminal only for systems and labs the team is explicitly authorized to test.
- The template is a general-purpose Kali shell; it is not isolated per OpsAegis user.
- Keep API, Postgres, Redis and other OpsAegis services private.
- The OpsAegis terminal link is role-gated in the UI, but the template's shared Basic Auth is the actual terminal login boundary. Anyone who has the shared credentials can reach the terminal URL directly.
- The template's `/data` volume persists data. Do not store personal credentials, private keys or unrelated sensitive data there.
