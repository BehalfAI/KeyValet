---
name: keyvalet-add
description: Store a new API key or token in KeyValet — you type it into a private dialog, it never passes through the chat
---

The user ran `/keyvalet-add`. If they included text after the command (e.g. a service such as `openai`/`github`/`stripe`, optionally followed by a credential name), use it as the hint below.

Goal: save a new credential in KeyValet. The user enters the secret in KeyValet's native dialog, so **never** ask them to paste it in the chat and never pass `value` yourself.

1. Work out the service from the hint (or from the conversation, e.g. the project's SDKs or the API being discussed). If there is no clue at all, ask in one short line which service the key is for.
2. Find the template with `credential_templates` (search by the service name). If nothing matches, use a generic one (`bearer`, `header`, `query` or `basic`) and ask for the API's base URL if needed.
3. Check `credential_list` for an existing credential of that service. If one exists, ask whether to replace it (`overwrite: true`) or add another under a new name.
4. Call `credential_set` with `template`, `name` (the hint's second word, else `default`, or the project/account it belongs to), any non-secret `fields`, and `purpose` = `User ran /keyvalet-add`. Leave out `value`: a dialog asks the user for the secret, and KeyValet verifies it when the template supports that.

Finish with one or two sentences: what was saved, whether verification passed, and how to use it (e.g. "ask me to call the OpenAI API through KeyValet").
