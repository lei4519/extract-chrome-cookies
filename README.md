# extract-chrome-cookies

Getting cookies by reading Chrome's cookie database on your computer.

Thanks to (chrome-cookies-secure)[https://github.com/bertrandom/chrome-cookies-secure], this is the rust version of it, why implement it again with Rust?
1. chrome-cookies-secure depends on the Node environment. If you want to use it in Go or Python, you must install Node first.
2. Even in the node environment, it doesn't work all the time. For example, when writing vscode extension, the `sqlite` dependency is not supported in vscode, so I had to fork the repo and change the dependency to `vscode-sqlite`.

Now, using Rust to turn it into an executable binary, we can call it from anywhere.

## Install

```sh
git clone git@github.com:lei4519/extract-chrome-cookies.git --depth=1 $HOME/.extract-chrome-cookies && $HOME/.extract-chrome-cookies/scripts/install
```

## Uninstall

```sh
extract-chrome-cookies unset-global-hook && rm /usr/local/bin/extract-chrome-cookies && rm -rf ~/.extract-chrome-cookies
```

## Use

```sh
extract-chrome-cookies -h
```

