import { Controller } from "@hotwired/stimulus";

export default class extends Controller {
  static targets = ["nav", "backdrop", "palette", "search", "commands"];

  connect() {
    this.boundClose = this.closePalette.bind(this);
  }

  disconnect() {
    this.boundClose = null;
  }

  shortcut(event) {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      this.openPalette();
    }

    if (event.key === "Escape") {
      this.closePalette();
      this.closeNav();
    }
  }

  toggleNav() {
    this.navTarget.classList.toggle("is-open");
    this.backdropTarget.classList.toggle("is-visible");
    document.body.classList.toggle("nav-open");
  }

  closeNav() {
    if (!this.hasNavTarget) return;
    this.navTarget.classList.remove("is-open");
    this.backdropTarget.classList.remove("is-visible");
    document.body.classList.remove("nav-open");
  }

  openPalette() {
    if (!this.hasPaletteTarget) return;
    this.paletteTarget.showModal();
    this.searchTarget.value = "";
    this.filterCommands();
    requestAnimationFrame(() => this.searchTarget.focus());
  }

  closePalette() {
    if (this.hasPaletteTarget && this.paletteTarget.open) this.paletteTarget.close();
  }

  dialogBackdrop(event) {
    if (event.target === this.paletteTarget) this.closePalette();
  }

  filterCommands() {
    const query = this.searchTarget.value.trim().toLowerCase();
    this.commandsTarget.querySelectorAll("a[data-command]").forEach((item) => {
      item.hidden = query.length > 0 && !item.dataset.command.toLowerCase().includes(query);
    });
  }

  openDialog(event) {
    const dialog = event.currentTarget.ownerDocument.getElementById(event.currentTarget.dataset.dialogId);
    if (dialog) dialog.showModal();
  }

  closeDialog(event) {
    event.currentTarget.closest("dialog")?.close();
  }
}
