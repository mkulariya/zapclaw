# Telegram Integration

Control ZapClaw remotely from Telegram. Only whitelisted users can issue commands — everyone else gets silently dropped.

## 1. Create the Bot

Open Telegram and message `@BotFather`:

```
/newbot
```

Follow the prompts to choose a name and username. Save the token it gives you:

```
1234567890:ABCDEFabcdef...
```

## 2. Lock Down the Bot

Still in `@BotFather`, run these two commands:

```
/setjoingroups → Disable
```
Prevents anyone from adding your bot to group chats.

```
/setprivacy → Enable
```
Bot only receives messages directed at it, not all chat traffic.

## 3. Get Your User ID

Message `@userinfobot` — it replies with your numeric user ID (e.g. `123456789`).

## 4. Configure ZapClaw

Set environment variables — **never use CLI flags**, they leak via `ps aux`:

```bash
export ZAPCLAW_TELEGRAM_TOKEN="1234567890:ABCDEFabcdef..."
export ZAPCLAW_TELEGRAM_ALLOWED_IDS="123456789"
```

Add these to your `.env` file or shell profile. Never commit them to git.

## 5. Run

```bash
zapclaw --enable-telegram
```

For unattended/automated use:

```bash
zapclaw --enable-telegram --no-confirm
```

## Verify

```bash
curl https://api.telegram.org/bot<your_token>/getMe
```

Should return your bot's info as JSON. Then send any message to your bot from Telegram — ZapClaw will respond.

## Security Model

| Property | Behavior |
|----------|----------|
| Whitelist | Only your user ID can execute commands |
| Silent drop | Unauthorized users get zero response |
| Group access | Disabled via `/setjoingroups` |
| Privacy mode | Enabled via `/setprivacy` |
| Token storage | Environment variable only — never in CLI args or config files |
| Rate limiting | 1 concurrent task per chat |
| Replay prevention | State persisted in `.telegram_state.json` |
| Transport | HTTPS to Telegram servers (TLS encrypted) |

> **Note:** Telegram's servers can read your messages — this is not end-to-end encrypted. Security is enforced by the whitelist, not the transport.
