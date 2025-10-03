import {
  savePostingAccount,
  getAllPostingAccounts,
  deletePostingAccount,
} from "./common/dataStorage.js";
import { mastodon } from "./common/mastodon.js";
import { bluesky } from "./common/bluesky.js";
import { safeFetch } from "./common/urlValidator.js";

/*
== Bluesky ===========================================================================================================
*/
async function saveBlueskyAccount(ev, account) {
  ev.target.disabled = true;
  console.log(account);

  account.name = `@${account.handle}`;
  account.type = "Bluesky";

  console.log(account);

  savePostingAccount(account);

  ev.target.disabled = false;

  refreshAccounts().then((e) => {
    m.redraw();
  });

  m.route.set("/AccountList");
}

const AddBluesky = {
  oninit: (vnode) => {
    vnode.state.account = {
      handle: "",
      password: "",
    };
    vnode.state.showPassword = false;
  },
  view: (vnode) => {
    let account = vnode.state.account;
    return m("form", [
      m("h3", "Add Bluesky Account"),
      m("label", { for: "handle" }, "Account Handle"),
      m("input[type=text]", {
        name: "handle",
        value: account["handle"],
        oninput: (e) => {
          account["handle"] = e.target.value;
        },
      }),
      m("label", { for: "password" }, "Application Password"),
      m("div", { style: "display: flex; gap: 0.5rem;" }, [
        m("input", {
          type: vnode.state.showPassword ? "text" : "password",
          name: "password",
          value: account["password"],
          style: "flex: 1;",
          oninput: (e) => {
            account["password"] = e.target.value;
          },
        }),
        m("button", {
          type: "button",
          onclick: () => { vnode.state.showPassword = !vnode.state.showPassword; }
        }, vnode.state.showPassword ? "Hide" : "Show"),
      ]),
      m("button", { onclick: (ev) => saveBlueskyAccount(ev, account) }, "Save"),
    ]);
  },
};

/*
== Mastodon ===========================================================================================================
*/
async function saveMastodonAccount(ev, account) {
  ev.target.disabled = true;
  console.log(account);
  let server = account.server;

  if (!server.includes("://")) {
    account.server = `https://${server}`;
    server = account.server;
  }

  let serverURL = new URL("/", server);
  /*
    BUG: This is the wrong method to call. It doesn't prove that the access token has read access to the profile.
    It proves if the profile exists, which is a plus. It needs a subsequent call to read the profile.
    */
  let profileURL = new URL(
    `/api/v1/accounts/lookup?acct=${account.handle}`,
    serverURL,
  ); // public call, if I go through normal mastodon.methodCall() it fails

  let response = await fetch(profileURL);
  let profileInfo;

  if (response.ok) {
    profileInfo = await response.json();
  } else {
    throw "Mastodon account error";
  }

  account.profileInfo = profileInfo;
  account.name = `@${account.handle}@${serverURL.hostname}`;
  account.type = "Mastodon";

  console.log(account);

  savePostingAccount(account);

  ev.target.disabled = false;

  refreshAccounts();
  m.route.set("/AccountList");
}

const AddMastodon = {
  oninit: (vnode) => {
    vnode.state.account = {
      handle: "",
      server: "",
      access_token: "",
    };
    vnode.state.showToken = false;
  },
  view: (vnode) => {
    let account = vnode.state.account;
    return m("form", [
      m("h3", "Add Mastodon Account"),
      m("label", { for: "handle" }, "Account Handle"),
      m("input[type=text]", {
        name: "handle",
        value: account["handle"],
        oninput: (e) => {
          account["handle"] = e.target.value;
        },
      }),
      m("label", { for: "server" }, "Mastodon server"),
      m("input[type=text]", {
        name: "server",
        value: account["server"],
        oninput: (e) => {
          account["server"] = e.target.value;
        },
      }),
      m("label", { for: "access_token" }, "Personal Access Token"),
      m("div", { style: "display: flex; gap: 0.5rem;" }, [
        m("input", {
          type: vnode.state.showToken ? "text" : "password",
          name: "access_token",
          value: account["access_token"],
          style: "flex: 1;",
          oninput: (e) => {
            account["access_token"] = e.target.value;
          },
        }),
        m("button", {
          type: "button",
          onclick: () => { vnode.state.showToken = !vnode.state.showToken; }
        }, vnode.state.showToken ? "Hide" : "Show"),
      ]),
      m(
        "button",
        { onclick: (ev) => saveMastodonAccount(ev, account) },
        "Save",
      ),
    ]);
  },
};

/*
== Micropub ===========================================================================================================
*/
async function saveMicropubAccount(ev, account) {
  ev.target.disabled = true;

  let url = new URL(account.link);

  let response = await safeFetch(url);

  if (!response.ok) {
    throw "Error adding Micropub account";
  }

  let data = await response.text();
  const parser = new DOMParser();
  const doc = parser.parseFromString(data, "text/html");
  const html = doc.documentElement;

  const micropubURL = html
    .querySelector(`link[rel="micropub"]`)
    .getAttribute("href");

  account.endpoint = micropubURL;
  account.name = account.link;
  account.type = "Micropub";

  savePostingAccount(account);

  ev.target.disabled = false;

  refreshAccounts();
  m.route.set("/AccountList");
}

const AddMicropub = {
  oninit: (vnode) => {
    vnode.state.account = {
      link: "",
      access_token: "",
    };
    vnode.state.showToken = false;
  },
  view: (vnode) => {
    let account = vnode.state.account;
    return m("form", [
      m("h3", "Add Micropub Account"),
      m("label", { for: "link" }, "Website"),
      m("input[type=text]", {
        name: "link",
        value: account["link"],
        oninput: (e) => {
          account["link"] = e.target.value;
        },
      }),
      m("label", { for: "access_token" }, "Access Token"),
      m("div", { style: "display: flex; gap: 0.5rem;" }, [
        m("input", {
          type: vnode.state.showToken ? "text" : "password",
          name: "access_token",
          value: account["access_token"],
          style: "flex: 1;",
          oninput: (e) => {
            account["access_token"] = e.target.value;
          },
        }),
        m("button", {
          type: "button",
          onclick: () => { vnode.state.showToken = !vnode.state.showToken; }
        }, vnode.state.showToken ? "Hide" : "Show"),
      ]),
      m(
        "button",
        { onclick: (ev) => saveMicropubAccount(ev, account) },
        "Save",
      ),
    ]);
  },
};

/*
== Account List ===========================================================================================================
*/

const AccountDisplay = {
  view: (vnode) => {
    let account = vnode.attrs.account;
    return m("li", [
      m("strong", account.name),
      m("span", `  (${account.type})  •  `),
      m(
        "a",
        {
          href: "#",
          onclick: (e) => {
            deletePostingAccount(account);
            refreshAccounts();
          },
        },
        "delete",
      ),
    ]);
  },
};

const AccountList = {
  view: (vnode) => {
    vnode.state.accounts = accounts;
    return m("section", [
      m("h3", "Accounts for posting"),
      vnode.state.accounts.length > 0
        ? m(
            "ul",
            vnode.state.accounts.map((account) =>
              m(AccountDisplay, { account }),
            ),
          )
        : m("strong", "Add posting accounts using the buttons below."),
      m(
        "nav",
        m("ol", [
          m(
            "li",
            m(
              m.route.Link,
              { selector: "button", href: "/AddMastodon" },
              "Add Mastodon Account",
            ),
          ),
          m(
            "li",
            m(
              m.route.Link,
              { selector: "button", href: "/AddBluesky" },
              "Add Bluesky Account",
            ),
          ),
          m(
            "li",
            m(
              m.route.Link,
              { selector: "button", href: "/AddMicropub" },
              "Add Micropub Account",
            ),
          ),
        ]),
      ),
      m("p", [
        "Open the documentation about ",
        m(
          "a",
          { href: "/docs/index.html#/postingaccounts", target: "_blank" },
          "managing posting accounts",
        ),
        ".",
      ]),
    ]);
  },
};

/*
== Initialisation ===========================================================================================================
*/

let accounts = [];

async function refreshAccounts() {
  let obj = await getAllPostingAccounts();

  let keys = Object.keys(obj);

  accounts = keys.map((k) => obj[k]);

  m.redraw();
}

refreshAccounts().then((accounts) => {
  const appRoot = document.getElementById("app");

  m.route(appRoot, "/AccountList", {
    "/AddMastodon": AddMastodon,
    "/AddBluesky": AddBluesky,
    "/AddMicropub": AddMicropub,
    "/AccountList": AccountList,
  });
});
