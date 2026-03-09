# SecretShare — Frontend

A modern SvelteKit frontend for creating self-destructing secret links.

## Features

- Share **text** or **files** via a secure, one-time link
- Configure the **maximum number of views** before the link self-destructs (Once / 5× / 10× / 25× / Custom)
- Optional **password protection** for extra security
- Drag-and-drop file upload
- Copy-to-clipboard for the generated link

## Development

Install dependencies:

```sh
npm install
```

Start the development server:

```sh
npm run dev
```

## Building

Create a production build:

```sh
npm run build
```

Preview the production build:

```sh
npm run preview
```

> To deploy, install an [adapter](https://svelte.dev/docs/kit/adapters) for your target environment.
