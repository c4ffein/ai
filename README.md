# ai
KISS LLM bridge to your terminal, in Python

## Help
```
ai - KISS LLM bridge to your terminal
─────────────────────────────────────
~/.config/ai/config.json     => {"api-key": "sk-ant-XXXX",
                                 "certificate": "XXXX",
                                 "root-certificate-path": "XXXX",
                                 "default-system-prompt":"shannon"}
~/.config/ai/system-prompts/ => directory to store system prompts by name
─────────────────────────────────────
- ai                                 ==> show usage
- ai "A question"                    ==> ask something
- ai "A question" file="file.md"     ==> ask something with an additional file
- ai "A question" model="claude-4"   ==> ask something with an specific model
- ai "A question" system="shannon"   ==> ask something with a specific system prompt, by name
- ai "A question" system="original"  ==> ask something ignoring the default-system-prompt config
- ai "A question" stream=true        ==> stream response in real-time
─────────────────────────────────────
- ai action=list-models              ==> list available models
─────────────────────────────────────
Only reaching out to Claude for now, will maybe add Le Chat from Mistral
```
