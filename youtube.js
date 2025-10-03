const player = document.getElementById("youtube-player");
const search = new URLSearchParams(location.search);

if (search.has("id")) {
  let id = search.get("id");
  // Validate YouTube video ID (alphanumeric chars, hyphens, or underscores, typically 8-16 chars)
  const youtubeIdPattern = /^[a-zA-Z0-9_-]{8,16}$/;
  if (youtubeIdPattern.test(id)) {
    let url = `https://www.youtube.com/embed/${encodeURIComponent(id)}`;
    player.src = url;
  } else {
    console.error("Invalid YouTube video ID");
  }
}
