import { ipcRenderer } from 'electron';

const appNameTitle = 'ConnectApp';

function changeDisable(disabled: boolean,
    connectDisabled : boolean | undefined = undefined) {
  const fieldNames = [
    'executeBtn',
    'connect',
  ];
  for (const name of fieldNames) {
    const field = document.getElementById(name);
    if (!field) {
      // do nothing
    } else if (name === 'connect') {
      if (typeof connectDisabled === 'boolean') {
        // field.disabled = connectDisabled;
      } else {
        // field.disabled = disabled;
      }
    } else {
      // field.disabled = disabled;
    }
  }
}

function checkDisconnect(arg: any) {
  let appName = document.getElementById('app-name');
  let connectResp = document.getElementById('connectResponse');
  let connect = document.getElementById('connect');
  if (!appName || !connectResp || !connect) {
    // do nothing
  } else if (('disconnect' in arg) && (arg.disconnect ===  true)) {
    changeDisable(true, false);
    appName.innerHTML = `${appNameTitle}: -`;
    connectResp.nodeValue = arg.errorMessage;
    // connect.disabled = false;
  } else {
    changeDisable(false, true);
  }
}

ipcRenderer.on("ledgerInfo", (event, arg) => {
  let appName = document.getElementById('app-name');
  let connectResp = document.getElementById('connectResponse');
  let connect = document.getElementById('connect');
  if (!appName || !connectResp || !connect) {
    // do nothing
  } else if (arg.success) {
    const ver = `v${arg.version.major}.${arg.version.minor}.${arg.version.patch}`
    appName.innerHTML = `${appNameTitle}: ${arg.name} (${ver})`;
    connectResp.nodeValue = 'connect';
    changeDisable(false, true);
  } else {
    changeDisable(true, false);
    appName.innerHTML = 'name: -';
    connectResp.nodeValue = arg.errorMessage;
    // connect.disabled = false;
  }
});

const connBtn = document.getElementById('connect');
if (connBtn != null) {
  connBtn.addEventListener('click', () => {
    changeDisable(true);
    const resp = document.getElementById('connectResponse');
    if (resp != null) {
      resp.nodeValue = 'check connection...';
      ipcRenderer.send('requestLedgerInfo');
    }
  });
}

const execBtn = document.getElementById('executeBtn');
if (execBtn != null) {
  execBtn.addEventListener('click', () => {
    changeDisable(true);
    const count = document.getElementById('count');

    if (count != null) {
      const value = count.getAttribute('value');
      if (typeof value == 'string') {
        parseInt(value, 10);
        ipcRenderer.send('requestSignTest', value);
      } 
    }
  });
}

// first execute
changeDisable(true);
ipcRenderer.send('requestLedgerInfo');
