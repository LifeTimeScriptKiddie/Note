```

#!/usr/bin/env python3 

import openai

openai.api_key = "get your own API key"

def generate_response(prompt):
  completions = openai.Completion.create(
    engine="text-davinci-002",
    prompt=prompt,
    max_tokens=1024,
    n=1,
    stop=None,
    temperature=0.5,
  )

  message = completions.choices[0].text
  return message.strip()

while True:
  user_input = input('Enter your message: ')
  if user_input == 'quit':
    break
  else:
    response = generate_response(user_input)
    print(response)

    # Save the conversation to a file
    with open('conversation.txt', 'a') as f:
      f.write(f'User: {user_input}\n')
      f.write(f'AI: {response}\n')

```