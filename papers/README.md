# IEEE paper

`ieee.tex` is a complete standalone document. Compile it directly; do not
include it from another document that already has `\documentclass`:

```bash
make paper
```

On Fedora, install the IEEE LaTeX class and packages first:

```bash
sudo dnf install texlive-scheme-medium texlive-ieeetran
```

The generated PDF and auxiliary files are written to `papers/build/`.
