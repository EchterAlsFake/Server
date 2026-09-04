---
title: "AI transparency statement"
summary: "Explains where AI assistance is used in the EAF ecosystem and the engineering principles governing its use."
public_url: "https://docs.echteralsfake.me/transparency/"
aliases:
  - "AI usage disclosure"
  - "artificial intelligence transparency"
keywords:
  - "AI assistance"
  - "documentation"
  - "engineering review"
  - "tool distribution"
  - "Philosophy"
---

# AI transparency statement

Explains where AI assistance is used in the EAF ecosystem and the engineering principles governing its use.

## Philosophy

I want to be explicit about where AI assistance is used, especially as generated code becomes common in public software.

**Core approach**
I use AI for focused assistance and repetitive work. Architecture, acceptance criteria, testing, and final decisions remain human responsibilities.

## Where AI is used

AI is applied to bounded tasks where it reduces mechanical work or helps investigate an unfamiliar implementation detail.

### Documentation

Structuring references, descriptions, and examples for review.

### Repository READMEs

Formatting introductions, feature summaries, and installation guidance.

### Server UI

Implementing and revising HTML templates and responsive CSS.

### Core networking

Investigating and reviewing async networking and connection handling.

### Logic and calculations

Assistance with progress reporting, terminal calculations, and async data flow.

## Engineering principles

I do not delegate entire projects or architectural ownership to a model. AI is used when a problem requires deeper investigation than a routine search, or when working in a language or concept outside my main expertise.

**Review and testing**
Python code and Qt interactions are reviewed and tested by a human before they are pushed.

The goal is to automate lower-value mechanical work and reserve human time for defining the problem, evaluating tradeoffs, and verifying that the result is useful.

Estimated authorship ratio **90% human / 10% AI-assisted** 90%

This is an estimated average from external tracking services and varies by project. The scraper packages are predominantly written by hand.

**Human ownership**
AI makes it possible to maintain several free and commercial projects in parallel, but responsibility for what ships remains with the developer.

## Tool distribution

Estimated distribution of AI tools used in the development workflow.

Gemini 3.1 Pro**80%**

80%

Claude Opus 4.6**15%**

15%

Gemini Flash 3.5**5%**

5%

### Bottom line

I understand and take responsibility for the code I publish. AI-assisted output is not pushed blindly.

## Related MCP documents

- [EAF Python API documentation overview](../overview.md)
- [Legal disclaimer for EAF API wrappers](../legal/disclaimer.md)

## Original public page

- [https://docs.echteralsfake.me/transparency/](https://docs.echteralsfake.me/transparency/)
