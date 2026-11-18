// Offline NFS settings regression of the actual embedded app. No network.
const assert = require('assert');
const {createPage,nativeState,clone,settle} = require('./setup_dom_harness.js');

const smbOnly=['nativeShareField','nativeShare2Field','smbUserField','smbPasswordField','shareName','shareName2','smbUser','smbPassword','pwToggle'];
const nfsOnly=['nfsExportField','nfsPathField','nfsPath2Field','nfsVersionField','nfsUidField','nfsGidField','nfsExport','nfsPath','nfsPath2','nfsVersion','nfsUid','nfsGid'];
function assertMode(app,nfs) {
  for(const id of smbOnly)assert.strictEqual(app.get(id).hidden,nfs,'SMB control visibility: '+id);
  for(const id of nfsOnly)assert.strictEqual(app.get(id).hidden,!nfs,'NFS control visibility: '+id);
  assert.strictEqual(app.get('serverLabel').textContent,nfs?'NFS server address':'PC address');
  if(nfs)assert(app.get('keepCredentialsField').hidden && !app.get('keepCredentials').checked);
}
function nfsState() {
  const state=nativeState();
  state.settings={server:'192.168.11.186',share:'',share2:'',user:'',passwordSaved:false,transport:'nfs',nfsExport:'/volume1/public',
    nfsPath:'emulation/ps5/games/folders',nfsPath2:'emulation/ps5/games/images',nfsVersion:4,nfsUid:1000,nfsGid:1000};
  state.setup.hasSavedCredentials=false;return state;
}
function fill(app,values) {
  for(const [id,value] of Object.entries(values)) {app.get(id).value=value;app.get(id).fire(id==='nfsVersion'?'change':'input');}
}
async function check() {
  // A saved SMB connection opens in SMB mode with the NFS controls hidden.
  const smb=createPage([nativeState(),nativeState(),nativeState()]);await settle();
  assert.strictEqual(smb.get('transport').value,'smb');assertMode(smb,false);
  assert(!smb.get('transport').disabled);

  // Switching to NFS hides the Windows sign-in and posts only NFS keys, with the same token.
  smb.get('transport').value='nfs';smb.get('transport').fire('change');assertMode(smb,true);
  fill(smb,{server:'192.168.11.186',nfsExport:' /volume1/public ',nfsPath:'emulation/ps5/games/folders',nfsPath2:'emulation/ps5/games/images',nfsVersion:'4',nfsUid:'1000',nfsGid:'1000'});
  assertMode(smb,true);
  smb.replies.push({ok:true,pending:true,operation:1,message:'Checking the NFS export.'});
  smb.get('setup').fire('submit');await settle();
  assert.strictEqual(smb.postCount(),1);
  const post=smb.calls.find(call=>call.url==='/api/setup');
  assert.strictEqual(post.options.headers['X-Blackwire-Token'],'f'.repeat(32));
  assert.deepStrictEqual(JSON.parse(post.options.body),{transport:'nfs',server:'192.168.11.186',nfsExport:'/volume1/public',
    nfsPath:'emulation/ps5/games/folders',nfsVersion:4,nfsUid:1000,nfsGid:1000,revision:3,nfsPath2:'emulation/ps5/games/images'});

  // A saved NFS connection loads every public field and shows server:/export.
  const saved=createPage([nfsState(),nfsState(),nfsState()]);await settle();
  assert.strictEqual(saved.get('transport').value,'nfs');assertMode(saved,true);
  assert.strictEqual(saved.get('server').value,'192.168.11.186');assert.strictEqual(saved.get('nfsExport').value,'/volume1/public');
  assert.strictEqual(saved.get('nfsPath').value,'emulation/ps5/games/folders');assert.strictEqual(saved.get('nfsPath2').value,'emulation/ps5/games/images');
  assert.strictEqual(saved.get('nfsVersion').value,'4');assert.strictEqual(saved.get('nfsUid').value,'1000');assert.strictEqual(saved.get('nfsGid').value,'1000');
  assert.strictEqual(saved.get('shareName').value,'');assert.strictEqual(saved.get('smbUser').value,'');
  assert.strictEqual(saved.get('savedShare').textContent,'192.168.11.186:/volume1/public/emulation/ps5/games/folders + 192.168.11.186:/volume1/public/emulation/ps5/games/images');
  assert.strictEqual(saved.get('savedPassword').textContent,'Not used for NFS');assert.strictEqual(saved.get('savedUser').textContent,'uid 1000, gid 1000');
  await saved.poll();assert.strictEqual(saved.postCount(),0);

  // Bad drafts never reach the console.
  for(const bad of [{nfsExport:'volume1/public'},{nfsPath:'/emulation'},{nfsPath2:'emulation/ps5/games/folders'},{nfsUid:'-1'},{nfsGid:'1.5'},{nfsUid:''},{nfsExport:''}]) {
    const app=createPage([nfsState(),nfsState()]);await settle();fill(app,bad);
    app.get('setup').fire('submit');await settle();assert.strictEqual(app.postCount(),0,'Posted bad draft '+JSON.stringify(bad));
  }

  // One root folder: no second folder key, so the console saves one source.
  const one=clone(nfsState());one.settings.nfsPath='';one.settings.nfsPath2=null;one.settings.nfsVersion=3;
  const single=createPage([one,clone(one),clone(one)]);await settle();
  assert.strictEqual(single.get('nfsPath2').value,'');assert.strictEqual(single.get('nfsVersion').value,'3');
  assert.strictEqual(single.get('savedShare').textContent,'192.168.11.186:/volume1/public');
  single.get('nfsUid').value='1001';single.get('nfsUid').fire('input');
  single.replies.push({ok:true,pending:true,operation:1,message:'Checking the NFS export.'});
  single.get('setup').fire('submit');await settle();
  const body=JSON.parse(single.calls.find(call=>call.url==='/api/setup').options.body);
  assert(!Object.hasOwn(body,'nfsPath2'));assert.strictEqual(body.nfsPath,'');assert.strictEqual(body.nfsUid,1001);assert.strictEqual(body.nfsVersion,3);
  for(const key of ['share','share2','smbUser','smbPassword','keepCredentials'])assert(!Object.hasOwn(body,key),'NFS body carried '+key);

  // Switching back to SMB restores the sign-in controls.
  single.get('transport').value='smb';single.get('transport').fire('change');assertMode(single,false);
  console.log('Offline NFS setup DOM: SMB/NFS switch, hidden sign-in, saved NFS fields, server:/export summary, bad drafts refused and exact NFS body passed.');
}
check().catch(error=>{console.error(error);process.exitCode=1;});
