'use strict';
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
let handler, sent, count = 0;
const notice = {hide() {return this;}, css() {return this;}, text() {return this;}, show() {return this;}};
const inputs = [
  {name: 'mkss_geo_restriction_enabled', checkbox: true, checked: true},
  {name: 'mkss_geo_allow_verified_ai', checkbox: true, checked: false},
  {name: 'mkss_geo_mode', value: 'allowlist'},
  {name: 'mkss_geo_allowed_countries', value: 'IN\nUS'}
];
const form = {find(selector) {
  if (selector === '.mkss-save-msg') return notice;
  return {each(callback) {inputs.forEach(input => callback.call(input));}};
}};
const button = {closest(selector) {assert.equal(selector, '.mkss-settings-form'); return form;}, prop() {return this;}};
const doc = {};
function $(target) {
  if (target === doc) return {on(event, selector, callback) {assert.equal(event, 'click'); assert.equal(selector, '.mkss-save-btn'); handler = callback;}};
  if (target === button) return button;
  return {is() {return target.checkbox === true;}, val() {return target.value;}};
}
$.post = function (url, data) {
  sent = {url, data};
  return {done(fn) {fn({success: true}); return this;}, fail(fn) {return this;}, always(fn) {fn(); return this;}};
};
vm.runInNewContext(fs.readFileSync(require('path').join(__dirname, '../assets/js/admin.js'), 'utf8'), {
  document: doc, jQuery: $, mkssData: {ajaxUrl: '/wp-admin/admin-ajax.php', nonce: 'test', savedText: 'Saved', errorText: 'Error'}
});
handler.call(button);
assert.equal(sent.url, '/wp-admin/admin-ajax.php'); count++;
assert.equal(sent.data.action, 'mkss_save_settings'); count++;
assert.equal(sent.data.nonce, 'test'); count++;
assert.equal(sent.data.settings.mkss_geo_restriction_enabled, '1'); count++;
assert.equal(sent.data.settings.mkss_geo_allow_verified_ai, '0'); count++;
assert.equal(sent.data.settings.mkss_geo_mode, 'allowlist'); count++;
assert.equal(sent.data.settings.mkss_geo_allowed_countries, 'IN\nUS'); count++;
assert.equal(Object.keys(sent.data.settings).length, 4); count++;
assert.equal(sent.data.settings.mkss_block_sql_injection, undefined); count++;
console.log(`PASS: ${count} admin save assertions; no HTTP requests sent.`);
