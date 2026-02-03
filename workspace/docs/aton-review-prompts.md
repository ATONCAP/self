# Aton Development Review Prompts

These prompts guide Aton through quality assurance after completing tasks. Aton should intelligently select which prompts to run based on the work completed.

## When to Use Each Prompt

| Prompt | Use After |
|--------|-----------|
| Plan & Research | Starting any new feature or major change |
| Implement Plan | Plan approval |
| Keep Going | Mid-implementation when multiple tasks remain |
| Code Quality Pass | Completing any code changes |
| Thorough Testing | Completing implementation |
| Review Last Task | Any task completion |
| Production Readiness | Before deployment/release |
| LARP Assessment | Before claiming work is "done" |

---

## Plan & Research

Before writing any code, analyze the problem space thoroughly.

**Requirements:**
1. Clarify the goal - what exactly needs to be built and why
2. Identify constraints, dependencies, and edge cases
3. Research existing patterns, APIs, or libraries that apply
4. Outline the architecture and data flow
5. List unknowns and risks

Do not simplify anything or stub it.

**Deliverable:** A written plan I can review before implementation begins. Ask clarifying questions if requirements are ambiguous.

---

## Implement Plan

Execute the agreed plan step-by-step.

**Requirements:**
1. Follow the plan sequentially, noting any deviations
2. Write real, functional code - no stubs, placeholders, or TODOs
3. Handle errors and edge cases as you go
4. Commit logical chunks with clear explanations

If you encounter blockers or the plan needs revision, stop and discuss before proceeding.

**Critical:** Always implement fully finished, fully fleshed out working production code. Do not use try/catch or fallbacks or other defensive programming patterns unless necessary. Do not stub code or TODO or simplify -- always do the most complete version, even if it's very complex.

---

## Keep Going

Continue working through all remaining tasks until complete.

For each item: implement it fully, verify it works, then move to the next. Don't stop to ask permission between items.

**Critical:** Always implement fully finished, fully fleshed out working production code. Do not use try/catch or fallbacks or other defensive programming patterns unless necessary. Do not stub code or TODO or simplify -- always do the most complete version, even if it's very complex.

**Deliverable:** A final summary of what was completed and anything that remains blocked.

---

## Code Quality Pass

Review and refactor the current code for quality.

**Criteria:**
1. **Compact** - remove dead code, redundancy, over-abstraction
2. **Concise** - simplify verbose logic, use idiomatic patterns
3. **Clean** - consistent naming, clear structure, proper formatting
4. **Capable** - handles edge cases, fails gracefully, performs well

Make sure work is fully finished. Show the refactored code with brief explanations of changes.

---

## Thorough Testing

Review test coverage -- make sure it is expanded beyond the happy path and covers all buttons, routes, flows, code etc.

**Requirements:**
1. Test boundary conditions and edge cases
2. Test error handling and invalid inputs
3. Test integration points with real dependencies where possible
4. Test concurrent/async behavior if applicable
5. Verify actual outputs match expected - inspect the data

Tests must exercise real code paths, not mocks of the code under test.

---

## Review Last Task

Audit what was just completed.

**Questions:**
1. Does it actually work - did you verify the output?
2. Does it solve the original problem or just part of it?
3. Did anything get skipped or deferred?
4. Are there assumptions that should be documented?
5. What could break this in production?

Give me an honest assessment, not a confident summary. After your assessment, make TODOs for each thing that is not completed, and fix.

---

## Production Readiness Validation

Final checklist before deployment.

**Verify:**
1. All tests pass with real execution, not mocked
2. Error handling covers failure modes with proper logging
3. Configuration is externalized, no hardcoded secrets
4. Performance is acceptable under expected load
5. Dependencies are pinned and security-scanned
6. Rollback path exists
7. Monitoring/alerting is in place

Demonstrate each item is satisfied with evidence, not assertions. If you find anything that needs to be fixed, make a TODO for it and then do all fix TODOs.

---

## LARP Assessment

Critically evaluate whether this code is real or performative.

**Check for:**
1. Stubbed functions that return fake data
2. Hardcoded values masquerading as dynamic behavior
3. Tests that mock away the actual logic being tested
4. Error handling that silently swallows failures
5. Async code that doesn't actually await
6. Validation that doesn't validate
7. Any code path that hasn't been executed and verified

Report findings honestly. If something looks functional but isn't proven, flag it. Once you've done your review, immediately fix every issue, step by step, from most complicated to simplest. Make sure to have TODOs to keep track.
