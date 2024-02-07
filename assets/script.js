import __wbg_init, { SecretKey, UserSecrets, Vault, hash_password } from './ft-crypto/ft_crypto.js';

/** @type {UserSecrets} */
let secrets = undefined;

/** @type {Vault} */
let vault = undefined;

await __wbg_init();
init_page_selects();
localize_stamps(document.body);
decrypt_messages(document.body);

/**
 * @param {HTMLDivElement} elem
 */
window.select_page = function(elem) {
  const pages = document.querySelectorAll('.page-select');
  for (const page of pages) page.classList.remove('active-page');
  elem.classList.add('active-page');
};

function init_page_selects() {
  const pages = document.querySelectorAll('.page-select');
  for (const page of pages) if (location.pathname.indexOf(page.innerHTML.trim()) !== -1)
    page.classList.add('active-page');
}

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

/**
 * @param {HTMLElement} elem
 */
function handle_focus(elem) {
  elem.querySelector('.focused')?.focus();
}

/**
 * @param {HTMLElement} elem
 */
function localize_stamps(elem) {
  for (const e of elem.getElementsByClassName('stamp')) try {
    e.innerHTML = new Date(e.innerHTML).toLocaleString();
  } catch (e) {
    console.log("broken data: ", e);
  }
}

/**
 * @param {HTMLElement} elem
 */
async function decrypt_messages(elem) {
  const the_class = 'encrypted'

  const vault = await get_vault();
  const encrypted = elem.getElementsByClassName(the_class);
  for (const e of encrypted) try {
    const chat_name = e.getAttribute('chat-name');
    if (!chat_name) throw new Error('No chat name');
    const raw_bytes = Uint8Array.from(atob(e.innerHTML), c => c.charCodeAt(0));
    const key = vault.get_chat_key(chat_name);
    if (!key) throw new Error('No key for chat');
    const decrypted_bytes = key.decrypt(raw_bytes);
    e.innerHTML = new TextDecoder().decode(decrypted_bytes);
  } catch (err) {
    console.error(err);
    e.innerHTML = 'Error decrypting message!';
  }
}

document.body.addEventListener('htmx:responseError', function(event) {
  if (event.detail.xhr.status === 401) window.logout();
});

document.body.addEventListener('htmx:configRequest', function(event) {
  const preprocessor = preprocess[event.detail.elt.getAttribute('preprocess')];
  if (preprocessor) return preprocessor(event);
});

document.body.addEventListener('htmx:load', function(event) {
    localize_stamps(event.detail.elt);
    decrypt_messages(event.detail.elt);
    handle_focus(event.detail.elt);
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
async function get_vault() {
  if (vault) return vault;

  const username = localStorage.getItem('username');
  if (!username) return window.logout();
  const secrets = get_secrets();
  const vault_bytes = await fetch(`/files/${username}/vault`)
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

  return vault = new Vault(decrypted_vault);
}

const preprocess = {
  login: function(event) {
    const params = event.detail.parameters;
    localStorage.setItem('username', params.username);
    // so that password is hard to remember and/or unreadable in case its revealed in the tools
    localStorage.setItem('password', btoa(params.password));
    params.password = hash_password(params.password, params.username);
  },
  register: function(event) {
    const params = event.detail.parameters;
    params.password = hash_password(params.password, params.username);
    params.confirm_password = params.password;
  },
};
