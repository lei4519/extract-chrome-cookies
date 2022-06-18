# extract-chrome-cookies

Getting cookies by reading Chrome's cookie database on your computer.

![demo](https://raw.githubusercontent.com/lei4519/picture-bed/main/images/demo-min.gif)

Thanks to [chrome-cookies-secure](https://github.com/bertrandom/chrome-cookies-secure), this is the rust version of it, why implement it again with Rust?
1. chrome-cookies-secure depends on the Node environment. If you want to use it in Go or Python, you must install Node first.
2. Even in the node environment, it doesn't work all the time. For example, when writing vscode extension, the `sqlite` dependency is not supported in vscode, so I had to fork the repo and change the dependency to `vscode-sqlite`.

Now, using Rust to turn it into an executable binary, we can call it from anywhere.

## Install

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/lei4519/extract-chrome-cookies/main/scripts/install)"
```

## Uninstall

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/lei4519/extract-chrome-cookies/main/scripts/uninstall)"
```

## Use

```sh
extract-chrome-cookies https://google.com
```

- Format cookies 

```sh
extract-chrome-cookies -f curl https://google.com
```

- For more details

```sh
extract-chrome-cookies -h
```

## FAQ

Q: Why not supported windows?

A: I can't find a Rust API equivalent to JS, and my knowledge of encryption/decryption is pretty poor. If you have the ability to implement them, you are welcome to submit the Pull Request

