import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitizeChat } from "../src/index.ts";

test("removes chat-template markers", () => {
  assert.equal(sanitizeChat("<|im_start|>system hi [INST]there[/INST] <<SYS>>x<</SYS>>"), "system hi there x");
});

test("removes control and invisible characters", () => {
  assert.equal(sanitizeChat("ol\u0000a​ mun\u0007do"), "ola mundo");
});

test("keeps line breaks but collapses long runs", () => {
  assert.equal(sanitizeChat("a\n\n\n\n\nb\nc"), "a\n\nb\nc");
});

test("caps the length", () => {
  assert.equal(sanitizeChat("x".repeat(50), { maxLength: 10 }).length, 10);
});

test("leaves normal text alone", () => {
  const text = "Olá! Quanto custa o plano anual? Preciso de 3 licenças.";
  assert.equal(sanitizeChat(text), text);
});
