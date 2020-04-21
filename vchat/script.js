// Generate random room name if needed
if (!location.hash) {
  location.hash = Math.floor(Math.random() * 0xFFFFFF).toString(16);
}
const roomHash = location.hash.substring(1);
const drone = new ScaleDrone('cU9z7ev26H7O3P2f');
const roomName = 'observable-' + roomHash;
const configuration = { iceTransportPolicy: "all", // set to "relay" to force TURN.
iceServers: [{ 
            urls: "stun:stun.l.google.com:19302" },
             { urls: "turn:buttstuff.ops-netman.net",
               username:"alce", credential:"doesntknowhowtocode" }] };
let room;
let pc;


function onSuccess() {};
function onError(error) {
  console.error(error);
};

drone.on('open', error => {
  if (error) {
    return console.error(error);
  }
  room = drone.subscribe(roomName);
  room.on('open', error => {
    if (error) {
      onError(error);
    }
  });

  room.on('members', members => {
    console.log('MEMBERS', members);
    
    const isOfferer = members.length === 2;
    startWebRTC(isOfferer);
  });
});


function sendMessage(message) {
  drone.publish({
    room: roomName,
    message
  });
}

function startWebRTC(isOfferer) {
  console.log('Starting WebRTC: ', isOfferer);
  pc = new RTCPeerConnection(configuration);


  pc.onicecandidate = event => {
    if (event.candidate) {
      sendMessage({'candidate': event.candidate});
    }
  };

  if (isOfferer) {
    pc.onnegotiationneeded = () => {
      pc.createOffer().then(localDescCreated).catch(onError);
    }
  }

  pc.ontrack = event => {
    const stream = event.streams[0];
    if (!remoteVideo.srcObject || remoteVideo.srcObject.id !== stream.id) {
      remoteVideo.srcObject = stream;
    }
  };

  navigator.mediaDevices.getUserMedia({
    audio: true,
    video: true,
  }).then(stream => {
    localVideo.srcObject = stream;
    stream.getTracks().forEach(track => pc.addTrack(track, stream));
  }, onError);

  // Listen to signaling data from Scaledrone
  room.on('data', (message, client) => {
    // Message was sent by us
    if (client.id === drone.clientId) {
      return;
    }

    if (message.sdp) {
      
      pc.setRemoteDescription(new RTCSessionDescription(message.sdp), () => {
        
        if (pc.remoteDescription.type === 'offer') {
          pc.createAnswer().then(localDescCreated).catch(onError);
        }
      }, onError);
    } else if (message.candidate) {
      pc.addIceCandidate(
        new RTCIceCandidate(message.candidate), onSuccess, onError
      );
    }
  });
}

function localDescCreated(desc) {
  pc.setLocalDescription(
    desc,
    () => sendMessage({'sdp': pc.localDescription}),
    onError
  );
}

var localMuted = false;
var remoteMuted = false;
var lVideoOff = false;
var foobar = false;

function muteLocal() {
  localMuted = !localMuted;
  console.log('Muting local', localMuted);
  localVideo.srcObject.getTracks()[0].enabled = localMuted;
}

function muteRemote() {
  remoteMuted = !remoteMuted;
  console.log('Muting remote', remoteMuted);
  remoteVideo.srcObject.getTracks()[0].enabled = remoteMuted;
}

function lVideoMute() {
  lVideoOff = !lVideoOff;
  console.log('disabling local video', lVideoOff);
  localVideo.srcObject.getVideoTracks()[0].enabled = lVideoOff;
}

function rVideoMute() {
  rVideoOff = !rVideoOff;
  console.log('disabling remote video', rVideoOff);
  rocalVideo.srcObject.getVideoTracks()[0].enabled = rVideoOff;
}

/*
  function lVideo() {
    lVideoOff = !lVideoOff;
    console.log(remoteVideo);
  
    if (lVideoOff) {
      //localVideo.srcObject = "";
      console.log('lVideoOff', lVideoOff);
    } else {
      localVideo.srcObject = stream;
    }
  }
*/
