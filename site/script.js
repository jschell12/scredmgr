const copyButton = document.querySelector("#copy-install");
copyButton.addEventListener("click", async () => {
  const code = document.querySelector("#install-command");
  const status = document.querySelector("#copy-status");
  try {
    await navigator.clipboard.writeText(code.textContent);
    copyButton.textContent = "Copied!";
    status.textContent = "Installation commands copied to clipboard.";
  } catch {
    const range = document.createRange();
    range.selectNodeContents(code);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    copyButton.textContent = "Commands selected";
    status.textContent =
      "Copy unavailable. Commands selected; use your keyboard to copy.";
  }
  setTimeout(() => {
    copyButton.textContent = "Copy commands";
  }, 3000);
});
