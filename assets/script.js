"use strict";

import __wbg_init, { EncPublicKey, SecretKey, UserSecrets, Vault, hash_password } from './ft-crypto/ft_crypto.js';

navigator.serviceWorker.register('/assets/service-worker.js', { type: 'module' });

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
  const old_username = get_username();
  
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

/**
 * @param {HTMLFormElement} form
 */
window.validate_chat_invite = function(form) {
  const pk_hash = form.elements['pk_hash'];
  if (!pk_hash) return;

  if (pk_hash.value === '') return report(pk_hash, 'Public key hash is required');
  const user_key = form.elements['user_key'];
  if (user_key.value === '') return report(pk_hash, 'Server did not snd user key, wath the heck?');

  let parsed_pk = undefined;
  try {
    parsed_pk = EncPublicKey.from_base64(user_key.value);
  } catch (e) {
    return report(pk_hash, 'Failed to parse user key, really now...');
  }

  let belongs_to_parsed_pk = undefined;
  try {
    belongs_to_parsed_pk = parsed_pk.verify_with_hash(pk_hash.value);
  } catch (e) {
    return report(pk_hash, `Hash you provided is invalid: ${e}`);
  }

  if (!belongs_to_parsed_pk)
    return report(pk_hash, 
      'Public key does not match the hash, either your hash is incorrect or server attempted to MITM.'
    );
};

/**
 * @param {HTMLButtonElement} button
 */
window.compute_pk_hash = function(button) { 
  const secs = get_secrets();
  if (!secs) return;

  console.log(secs.enc.public_key.hash());

  navigator.clipboard.writeText(secs.enc.public_key.hash());

  const prev = button.innerHTML;
  button.innerHTML = '~~~~copied~~~~';
  setTimeout(() => button.innerHTML = prev, 1000);
};

window.logout = function() {
  const has_session = cookieExists('session');
  deleteCookie('session');
  sessionStorage.clear();
  if (has_session) location.replace('/');
};

/**
 * @param {KeyboardEvent} event
 */
window.filter_enter = function(event) {
  if (event.key !== 'Enter' || event.ctrlKey || event.shiftKey) return;
  htmx.trigger("#send-prompt", "submit");
  event.preventDefault();
}

/** @type {{ username: string, password: string, secs: UserSecrets } | undefined} */
let secrets = undefined;

/**
  * In case of failure we logout.
  * @returns {UserSecrets}
  */
function get_secrets() {
  const username = get_username();
  const password = get_password();

  if (!username) return window.logout();
  if (!password) return window.logout();

  if (secrets?.password === password
    && secrets?.username === username) return secrets;

  return secrets = new UserSecrets(password, username);
}

await __wbg_init();
/** @type {Vault} */
const vault = await load_vault();

update_page_selects();
postprocess_html(document.body);


async function save_vault() {
  const username = get_username();
  if (!username) return window.logout();

  const bytes = vault.to_bytes();
  const secs = get_secrets();
  const encrypted_bytes = secs.master_secret.encrypt(bytes);
  const blob = new Blob([encrypted_bytes], { type: 'application/octet-stream' });

  await fetch(`/vaults`, { method: 'POST', body: blob })
    .catch(e => console.error('saving vault failed:', e));
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

function update_page_selects(pathname = location.pathname) {
  const pages = document.querySelectorAll('.page-select');
  for (const page of pages) if (pathname.indexOf(page.innerHTML.trim()) !== -1) {
    page.classList.add('active-page');
  } else {
    page.classList.remove('active-page');
  }
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
    console.error("broken data: ", e);
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
    // so that password is hard to remember and/or unreadable in case its revealed in the tools
    // on accident
    set_password(params.password);
    params.password = hash_password(params.password, params.username);
  },
  register: function(event) {
    const params = event.detail.parameters;
    const secrets = new UserSecrets(params.password, params.username);
    params.password = hash_password(params.password, params.username);
    params.confirm_password = params.password;
    params.public_key = secrets.enc.public_key.as_base64();
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
      let secs = get_secrets();
      if (!secs) throw new Error('No secrets');

      const params = event.detail.parameters;
      params.public_key = secs.enc.public_key.as_base64();
      if (!params.old_password) return;
      
      const username = get_username();
      if (!username) throw new Error('No username');

      if (params.username !== username && params.new_password === '') {
        secs = new UserSecrets(params.old_password, params.username);
        params.new_password = hash_password(params.old_password, params.username);
        params.old_password = hash_password(params.old_password, username);
      } else {
        secs = new UserSecrets(params.new_password, params.username);
        params.new_password = hash_password(params.new_password, params.username);
        params.old_password = hash_password(params.old_password, username);
      }
      params.public_key = secs.enc.public_key.as_base64();
      params.confirm_password = params.new_password;
    } catch (e) {
      console.error('profile preprocess failed:', e);
      event.detail.parameters = {};
      return window.logout();
    }

  },
  chat_invite: function(event) {
    const secs = get_secrets();
    if (!secs) return window.logout();

    const params = event.detail.parameters;
    if (!params.user_key) return;
    let key = undefined;
    try {
      key = EncPublicKey.from_base64(params.user_key);
    } catch (e) {
      return console.error('Failed to parse key:', e);
    }

    const chat_name = get_current_chat_name();
    if (!chat_name) return console.error('No chat name, but yet... chat invite?');

    const chat_sec = vault.get_chat_key(chat_name);
    if (!chat_sec) return console.error('No chat key for chat:', chat_name);

    params.ciphertext = secs.enc.encapsulate(key, chat_sec);
  },
  handle_invite: function(event) {
    const params = event.detail.parameters;

    if (params.decline)
      return event.detail.parameters = { command: 'decline' };

    const secs = get_secrets();
    if (!secs) return window.logout();

    if (!params.ciphertext) return console.error('No ciphertext, what?');
    if (!params.chat) return console.error('No chat name, what?');
    if (!vault) return window.logout();

    let chat_sec = undefined 
    try {
      chat_sec = secs.enc.decapsulate(params.ciphertext);
    } catch (e) {
      console.error('Failed to decapsulate:', e);
      return event.detail.parameters = { command: 'failed' };
    }

    vault.save_chat_key(params.chat, chat_sec);
    save_vault();
    event.detail.parameters = { command: 'accept' };
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
  profile: async function(_, failed) {
    if (Boolean(failed)) return;
    await save_vault();
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

document.body.addEventListener('htmx:historyRestore', function(event) {
  update_page_selects(event.detail.path);
});


/**
 * In case of failure we logout.
 * @returns {Promise<Vault>}
 */
async function load_vault() {
  const username = get_username();
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

/**
  * @returns {string | undefined}
  */
function get_current_chat_name() {
  return document.getElementById('chat-name')?.innerHTML;
}

/**
 * @return {string | undefined}
 */
function get_username() {
  return document.getElementById('nav-username')?.innerHTML?.trim() ?? window.logout();
}

/**
 * @return {string | undefined}
 */
function get_password() {
  const pass = sessionStorage.getItem('password');
  if (!pass) return window.logout();
  try {
    return atob(pass);
  } catch(e) {
    return window.logout();
  }
}

/**
 * @param {string} password
 */
function set_password(password) {
  sessionStorage.setItem('password', btoa(password));
}
