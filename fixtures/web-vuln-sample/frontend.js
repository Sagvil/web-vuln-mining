export function renderPreview(value) {
  document.querySelector("#preview").innerHTML = value;
}

export function goNext(destination) {
  window.location = destination;
}
