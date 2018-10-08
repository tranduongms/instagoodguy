'use strict';

const Client = require('../libs/client');

(async function () {
  var client = new Client('kennisonkenda', 'XvuZZ79ZR1');
  await client.login();
  let res = await client.getFeedByUsername('kennisonkenda');
  let res = await client.followUser('kennisonkenda');
  console.log(res);
})()
