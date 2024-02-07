import __wbg_init, { SecretKey, UserSecrets, Vault, hash_password } from './ft-crypto/ft_crypto.js';

/** @type {UserSecrets} */
let secrets = undefined;


await __wbg_init();
/** @type {Vault} */
const vault = await load_vault();

init_page_selects();
postprocess_html(document.body);

/**
 * @param {HTMLDivElement} elem
 */
window.select_page = function(elem) {
  const pages = document.querySelectorAll('.page-select');
  for (const page of pages) page.classList.remove('active-page');
  elem.classList.add('active-page');
};

/** 
  * @param {HTMLFormElement} form
  */
window.validate_login = function(form) {
  const password = form.elements['password'];
  report(password, validate_password(password));
};

window.validate_register = function(form) {
  /** @type {HTMLInputElement} */
  const username = form.elements['username'];
  /** @type {HTMLInputElement} */
  const password = form.elements['password'];
  /** @type {HTMLInputElement} */
  const confirm_password = form.elements['confirm_password'];

  console.log(password.value, confirm_password.value);
  if (password.value !== confirm_password.value) {
    report(confirm_password, 'Passwords do not match');
    return;
  }

  report(password, validate_password(password, username.value));
  report(confirm_password, '');
};

window.logout = function() {
  deleteCookie('session');
  localStorage.clear();
  location.replace('/');
};

/**
 * @param {string} name
 */
window.ensure_chat_key = async function(name) {
  if (!vault) return window.logout();
  if (vault.get_chat_key(name)) return;
  vault.save_chat_key(name, new SecretKey())
  await save_vault();
};

async function save_vault() {
  const username = localStorage.getItem('username');
  if (!username) return window.logout();

  const bytes = vault.to_bytes();
  console.log(bytes);
  const secrets = get_secrets();
  const encrypted_bytes = secrets.master_secret.encrypt(bytes);
  const blob = new Blob([encrypted_bytes], { type: 'application/octet-stream' });

  await fetch(`/vaults`, { method: 'POST', body: blob })
    .catch(console.log);
  console.log('vault saved');
}

/**
 * @param {HTMLElement} elem
 */
function postprocess_html(elem) {
  localize_stamps(elem);
  decrypt_messages(elem);
  make_textareas_auto_grow(elem);
  handle_focus(elem);
}

function init_page_selects() {
  const pages = document.querySelectorAll('.page-select');
  for (const page of pages) if (location.pathname.indexOf(page.innerHTML.trim()) !== -1)
    page.classList.add('active-page');
}

/**
 * @param {HTMLElement} elem
 */
function localize_stamps(elem) {
  const stamps = elem.querySelectorAll('.stamp');

  for (const e of stamps) try {
    e.innerHTML = new Date(e.innerHTML).toLocaleString();
    e.classList.remove('stamp');
  } catch (e) {
    console.log("broken data: ", e);
    e.innerHTML = 'Error parsing date!';
  }
}

/**
 * @param {HTMLElement} elem
 */
function decrypt_messages(elem) {
  if (!vault) return window.logout();

  const encrypted = elem.querySelectorAll(`.encrypted`);
  for (const e of encrypted) try {
    const chat_name = e.getAttribute('chat-name');
    if (!chat_name) throw new Error('No chat name');

    const key = vault.get_chat_key(chat_name);
    if (!key) throw new Error('No key for chat');

    const raw_bytes = Uint8Array.from(atob(e.innerHTML), c => c.charCodeAt(0));
    const decrypted_bytes = key.decrypt(raw_bytes);
    e.innerHTML = new TextDecoder().decode(decrypted_bytes);
  } catch (err) {
    console.error(err);
    e.innerHTML = 'Error decrypting message!';
  }

  for (const e of encrypted) e.classList.remove('encrypted');
}

/**
 * @param {HTMLElement} elem
 */
function make_textareas_auto_grow(elem) {
  const textareas = elem.querySelectorAll('textarea');
  for (const textarea of textareas) {
    textarea.addEventListener('input', function() {
      this.style.height = 'auto';
      this.style.height = this.scrollHeight + 'px';
    });
  }
}

/**
 * @param {HTMLElement} elem
 */
function handle_focus(elem) {
  elem.querySelector('.focused')?.focus();
}


document.body.addEventListener('htmx:responseError', function(event) {
  if (event.detail.xhr.status === 401) window.logout();
});

document.body.addEventListener('htmx:configRequest', function(event) {
  const preprocessor = preprocess[event.detail.elt.getAttribute('preprocess')];
  if (preprocessor) return preprocessor(event);
});

document.body.addEventListener('htmx:load', function(event) {
  postprocess_html(event.detail.elt);
});

/**
  * In case of failure we logout.
  * @returns {UserSecrets}
  */
function get_secrets() {
  if (secrets) return secrets;

  const username = localStorage.getItem('username');
  if (!username) return window.logout();
  let password = localStorage.getItem('password');
  if (!password) return window.logout();

  try {
    password = atob(password);
  } catch (e) {
    return window.logout();
  }

  return secrets = new UserSecrets(password, username);
}

/**
 * In case of failure we logout.
 * @returns {Promise<Vault>}
 *
 */
async function load_vault() {
  const username = localStorage.getItem('username');
  if (!username) return;

  const secrets = get_secrets();
  const vault_bytes = await fetch(`/vaults`)
    .then(r => r.arrayBuffer())
    .catch(e => {
      console.error("fetching vault failed: ", e);
      return new ArrayBuffer();
    });
  let decrypted_vault;
  try {
    decrypted_vault = secrets.master_secret.decrypt(new Uint8Array(vault_bytes));
  } catch (e) {
    decrypted_vault = new Uint8Array();
  }

  return new Vault(decrypted_vault);
}

const preprocess = {
  login: function(event) {
    const params = event.detail.parameters;
    localStorage.setItem('username', params.username);
    // so that password is hard to remember and/or unreadable in case its revealed in the tools
    // on accident
    localStorage.setItem('password', btoa(params.password));
    params.password = hash_password(params.password, params.username);
  },
  register: function(event) {
    const params = event.detail.parameters;
    params.password = hash_password(params.password, params.username);
    params.confirm_password = params.password;
  },
  send_message: function(event) {
    if (!vault) return window.logout();

    const params = event.detail.parameters;

    const key = vault.get_chat_key(params.name);
    if (!key) return console.error('No key for chat name:', params.name);

    const bytes = key.encrypt(new TextEncoder().encode(params.content));
    params.content = btoa(String.fromCharCode(...bytes));
  },
};

/**
 * @param {string} name
 */
function deleteCookie(name) {
  document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT; path=/';
}

/**
  * @param {HTMLInputElement} password
  * @returns {string}
  */
function validate_password(password) {
  if (!/[A-Z]/.test(password.value)) return 'missing uppercase letter';
  if (!/[a-z]/.test(password.value)) return 'missing lowercase letter';
  if (!/[0-9]/.test(password.value)) return 'missing number';
  return '';
}

/**
  * @param {HTMLInputElement} elem
  * @param {string} message
  */
function report(elem, message) {
  elem.setCustomValidity(message);
  elem.reportValidity();
}

