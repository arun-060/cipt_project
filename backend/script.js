const videoList = [
    "video1.mp4",
    "video2.mp4",
    "video3.mp4",
    "video4.mp4"
  ];
  
  const selector = document.getElementById('videoSelector');
  const player = document.getElementById('videoPlayer');
  const playBtn = document.getElementById('playBtn');
  
  // Fill dropdown with video names
  videoList.forEach(video => {
    const option = document.createElement('option');
    option.value = video;
    option.text = video;
    selector.appendChild(option);
  });
  
  // Play selected video
  playBtn.addEventListener('click', () => {
    const selectedVideo = selector.value;
    player.src = `videos/${selectedVideo}`;
    player.load();
    player.play();
  });
  