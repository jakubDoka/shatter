import __wbg_init, { SecretKey, UserSecrets, Vault, hash_password } from './ft-crypto/ft_crypto.js';

/**
 * @param {HTMLInputElement} elem
 */
window.change_color = function(elem) {
  const name = elem.name.replace('_', '-');
  const value = elem.value;
  document.documentElement.style.setProperty(`--${name}`, value);
};

/** @type {boolean} */
let theme_applied = false;

/**
 * @param {HTMLButtonElement} button
 * @param {string} form_id
 */
window.apply_theme = function(button, form_id) {
  const form = document.getElementById(form_id);
  if (!form) return console.error('No form with id:', form_id);

  const inputs = form.querySelectorAll('input[type="color"]');
  if (theme_applied) {
    for (const input of inputs) input.value = document.documentElement.style
      .removeProperty(`--${input.name.replace('_', '-')}`);
    button.innerHTML = 'try';
  } else {
    for (const input of inputs) window.change_color(input);
  }
  theme_applied = !theme_applied;
};

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

/** 
  * @param {HTMLFormElement} form
  */
window.validate_register = function(form) {
  /** @type {HTMLInputElement} */
  const username = form.elements['username'];
  /** @type {HTMLInputElement} */
  const password = form.elements['password'];
  /** @type {HTMLInputElement} */
  const confirm = form.elements['confirm_password'];

  console.log(password.value, confirm.value);
  if (password.value !== confirm.value)
    return report(confirm, 'Passwords do not match');

  report(password, validate_password(password, username.value));
  report(confirm, '');
};

/** 
  * @param {HTMLFormElement} form
  */
window.validate_profile = function(form) {
  /** @type {HTMLInputElement} */
  const new_username = form.elements['username'];
  /** @type {string} */
  const old_username = localStorage.getItem('username');
  
  const username_changed = new_username.value !== old_username;

  /** @type {NodeListOf<HTMLInputElement>} */
  const passwords = form.querySelectorAll('input[type="password"]');
  const [old, new_, confirm] = passwords;

  let passwords_required = false;
  for (const p of passwords) passwords_required |= p.value !== '';

  if (!passwords_required && !username_changed) return;
  if (username_changed && old.value === '')
    return report(old, 'Old password is required when changing username');

  for (const p of passwords) if (p.value === '' && !username_changed)
    return report(p, 'Password is required');
  

  if (new_.value !== confirm.value)
    return report(confirm, 'Passwords do not match');
  report(confirm, '');

  if (old.value === new_.value)
    return report(new_, 'New password must be different from the old one');

  for (const p of passwords) validate_password(p);
};

window.logout = function() {

  const has_session = cookieExists('session');
  deleteCookie('session');
  localStorage.clear();
  if (has_session) location.replace('/');
};

/** @type {UserSecrets} */
let secrets = undefined;

await __wbg_init();
/** @type {Vault} */
const vault = await load_vault();

init_page_selects();
postprocess_html(document.body);


async function save_vault() {
  const username = localStorage.getItem('username');
  if (!username) return window.logout();

  const bytes = vault.to_bytes();
  console.log(bytes);
  const secs = get_secrets();
  const encrypted_bytes = secs.master_secret.encrypt(bytes);
  const blob = new Blob([encrypted_bytes], { type: 'application/octet-stream' });

  await fetch(`/vaults`, { method: 'POST', body: blob })
    .catch(e => console.log('saving vault failed:', e));
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
  profile: function(event) {
    try {
      const params = event.detail.parameters;
      if (!params.old_password) return;
      
      const username = localStorage.getItem('username');
      if (!username) throw new Error('No username');

      if (params.username !== username && params.new_password === '') {
        params.new_password = hash_password(params.old_password, params.username);
        params.old_password = hash_password(params.old_password, username);
      } else {
        params.new_password = hash_password(params.new_password, params.username);
        params.old_password = hash_password(params.old_password, username);
      }
      params.confirm_password = params.new_password;

    } catch (e) {
      console.error('profile preprocess failed:', e);
      event.detail.parameters = {};
      return window.logout();
    }
  },
};

document.body.addEventListener('htmx:configRequest', function(event) {
  const preprocessor = preprocess[event.detail.elt.getAttribute('preprocess')];
  if (preprocessor) return preprocessor(event);
});

const postprocess = {
  create_chat: async function(_, chat_name) {
    vault.save_chat_key(chat_name, new SecretKey())
    await save_vault();
  },
  profile: async function(_, username) {
    const old_username = localStorage.getItem('username');
    if (old_username === username) return;

    secrets = undefined;
    await save_vault();

    localStorage.setItem('username', username);
    for (const name_div of document.querySelectorAll(`.username-${old_username}`)) {
      name_div.innerHTML = username;
      name_div.classList.remove(`username-${old_username}`);
      name_div.classList.add(`username-${username}`);
    }
  },
};

document.body.addEventListener('htmx:load', function(event) {
  postprocess_html(event.detail.elt);
  const postprocessor_call = event.detail.elt.getAttribute('postprocess');
  if (postprocessor_call) {
    const [postprocessor, ...args] = postprocessor_call.split(';');
    postprocess[postprocessor]?.(event, ...args);
  }
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

/**
 * @param {string} name
 */
function deleteCookie(name) {
  document.cookie = name + '=; expires=Thu, 01 Jan 1970 00:00:01 GMT; path=/';
}

/**
 * @param {string} name
 * @returns {boolean}
 */
function cookieExists(name) {
  return document.cookie.split(';').some(c => c.trim().startsWith(name + '='));
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

