# Execute pdf and sends the output to Chat GPT to explain it

## Usage:

### env:
    * export OPENAI_API_KEY='sk-32a1' (required) OpenAi api key
    * export OPENAI_API_MODEL='gpt-3.5-turbo' (optional) OpenAi model to use. Defaults to gpt-3.5-turbo

### command:
    * `!pipe python ./r2gpt.py`
    * Can also use a custom prompt to which the assembly code will be appended to:
      * `!pipe python ./r2gpt.py 'Why am I doing this?'`