'use strict';

const Client = require('../libs/client');

(async function () {
  var client = new Client('heiketsugindo', 'xobq6pcs');
  await client.login();
  let res = await client.postPhoto('./test.jpg', 'Hoho');
  console.log(res);
})()
