// Helper function to send POST requests
async function postData(url = '', data = {}) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return response.json();
}

async function initializeVault() {
  const masterPassword = document.getElementById('masterPassword').value;
  if (!masterPassword) {
    alert("Master password can't be empty");
    return;
  }
  const result = await postData('/initialize', { master_password: masterPassword });
  document.getElementById('initResult').textContent = result.message;
}

async function addPassword() {
  const masterPassword = document.getElementById('masterPassword').value;
  const site = document.getElementById('site').value;
  const password = document.getElementById('password').value;
  if (!masterPassword || !site || !password) {
    alert("All fields are required.");
    return;
  }
  const result = await postData('/add', { master_password: masterPassword, site, password });
  document.getElementById('addResult').textContent = result.message;
}

async function retrievePassword() {
  const masterPassword = document.getElementById('masterPassword').value;
  const site = document.getElementById('site').value;
  if (!masterPassword || !site) {
    alert("Both fields are required.");
    return;
  }
  const result = await postData('/retrieve', { master_password: masterPassword, site });
  if (result.password) {
    document.getElementById('retrievedPassword').textContent = `Password: ${result.password}`;
  } else {
    document.getElementById('retrievedPassword').textContent = result.message;
  }
}
function generatePassword() {
  fetch('/generate')
    .then(res => res.json())
    .then(data => {
      document.getElementById('generatedPassword').value = data.password;
      document.getElementById('strengthLabel').textContent = `Strength: ${data.strength}`;
    })
    .catch(() => alert("Error generating password"));
}

function copyPassword() {
  const pwdField = document.getElementById('generatedPassword');
  pwdField.select();
  pwdField.setSelectionRange(0, 99999); // For mobile devices
  navigator.clipboard.writeText(pwdField.value);
  alert("Password copied to clipboard!");
}

function checkStrength() {
  const pwd = document.getElementById('passwordToCheck').value;
  if (!pwd) {
    alert("Please enter a password");
    return;
  }
  fetch('/strength', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({password: pwd})
  })
    .then(res => res.json())
    .then(data => {
      document.getElementById('strengthResult').textContent = `Strength: ${data.strength}`;
    })
    .catch(() => alert("Error checking strength"));
}

