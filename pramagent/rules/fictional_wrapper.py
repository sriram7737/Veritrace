"""
pramagent.rules.fictional_wrapper
=================================
"Wrap a harmful request in fiction" bypass corpus.

These are the prompt patterns where the user asks for a story / roleplay /
hypothetical scenario whose subject is the harmful instruction they actually
want. The fiction frame is the bypass; the underlying request is unchanged.

Source: JailbreakBench fiction class, HarmBench scenario class, and the
"Persona Modulation Attacks" literature.

Most rules here ESCALATE rather than BLOCK — legitimate creative writing is a
real use case, and a human reviewer is the right judge.
"""
from __future__ import annotations

from ..layers import Rule
from ..types import Verdict


_PATTERNS: list[tuple[str, str, str, Verdict]] = [
    # "Write a story where the character explains how to ..."
    ("fw_story_character_explains",
     r"(?:write|tell|create)\s+(?:me\s+)?a\s+(?:story|scene|chapter|dialogue)\s+(?:where|in\s+which)\s+(?:a|the)\s+(?:character|protagonist|villain|hacker|chemist)\s+(?:explains|describes|details|teaches)\s+how\s+to",
     "Fiction: character-explains-how-to", Verdict.ESCALATE),

    # Roleplay framing
    ("fw_roleplay_unrestricted",
     r"(?:role.?play|let'?s\s+pretend|imagine\s+you\s+are)\s+(?:as\s+)?(?:a|the)\s+\w+\s+(?:who|that)\s+(?:has\s+no\s+(?:rules|restrictions|filters)|will\s+answer\s+anything|never\s+refuses)",
     "Fiction: unrestricted roleplay", Verdict.BLOCK),

    # "In a hypothetical world where X is legal ..."
    ("fw_hypothetical_legal",
     r"in\s+a\s+(?:hypothetical|fictional|alternate|parallel)\s+(?:world|universe|reality|scenario)\s+where\s+\w+\s+(?:is|are)\s+(?:legal|allowed|encouraged)",
     "Fiction: hypothetical-legality frame", Verdict.ESCALATE),

    # "For a screenplay / novel / movie, I need ..."
    ("fw_screenplay_need",
     r"(?:for|in)\s+(?:my|a)\s+(?:screenplay|novel|movie|video\s+game|short\s+story)\s*,?\s+i\s+need\s+(?:the\s+)?(?:exact|detailed|step.?by.?step)",
     "Fiction: screenplay-realism request", Verdict.ESCALATE),

    # "My character is a chemist / hacker / forger ..."
    ("fw_my_character_is",
     r"my\s+(?:character|protagonist|villain|main\s+character)\s+is\s+(?:a|an)\s+(?:chemist|hacker|bomb.?maker|forger|hitman|drug\s+dealer)",
     "Fiction: character-profession cover", Verdict.ESCALATE),

    # DAN-style "your character DAN..." persona attacks
    ("fw_persona_modulation",
     r"(?:from\s+now\s+on|going\s+forward)\s+you\s+(?:are|will\s+act\s+as|will\s+play)\s+(?:a|an)\s+\w+\s+(?:who|that)\s+(?:will|can|must)\s+(?:answer|do|say)\s+anything",
     "Fiction: persona-modulation attack", Verdict.BLOCK),

    # "Continue this story..." with seeded harmful content
    ("fw_continue_story_harmful_seed",
     r"continue\s+(?:this|the)\s+(?:story|narrative|scene).{0,80}(?:bomb|explosive|weapon|drug|kill|attack|exploit)",
     "Fiction: harmful continuation seed", Verdict.ESCALATE),

    # "Write dialogue between an AI with no rules and a curious user ..."
    ("fw_dialogue_no_rules_ai",
     r"(?:write|create)\s+(?:a\s+)?dialogue\s+between\s+(?:an?\s+)?(?:ai|assistant|model)\s+(?:with|that\s+has)\s+no\s+(?:rules|restrictions|filters)",
     "Fiction: dialogue-with-unrestricted-AI", Verdict.BLOCK),

    # "As an actor preparing for the role of ..."
    ("fw_actor_preparing",
     r"(?:as|i'?m)\s+an\s+actor\s+preparing\s+for\s+(?:a|the)\s+role\s+of\s+(?:a|an)\s+(?:terrorist|hitman|bomb.?maker|chemist|drug\s+dealer|hacker)",
     "Fiction: actor-preparation framing", Verdict.ESCALATE),

    # Movie-script formatting smuggled
    ("fw_movie_script_format",
     r"FADE\s+IN:.{0,200}(?:bomb|explosive|weapon|drug\s+synthesis|exploit\s+code)",
     "Fiction: movie-script formatting wrap", Verdict.ESCALATE),

    # "Granted three wishes ..." / fable framing
    ("fw_fable_wishes",
     r"(?:granted|given)\s+(?:three\s+)?wishes.{0,100}(?:how\s+to|steps?\s+to)\s+(?:make|build|synthesi[sz]e)",
     "Fiction: fable-cover request", Verdict.ESCALATE),

    # "If you were free of OpenAI / Anthropic rules ..."
    ("fw_if_you_were_free",
     r"if\s+you\s+(?:were|could\s+be)\s+free\s+(?:of|from)\s+(?:openai|anthropic|google|meta|your\s+(?:training|alignment|rules))",
     "Fiction: counterfactual-self frame", Verdict.BLOCK),

    # "Pretend the year is 2050 and X is normal ..."
    ("fw_future_year_normal",
     r"pretend\s+(?:the\s+year\s+is|it'?s)\s+\d{4}\s+and\s+\w+\s+(?:is|are)\s+(?:now\s+)?(?:normal|legal|common|encouraged)",
     "Fiction: future-acceptance frame", Verdict.ESCALATE),
]


FICTIONAL_WRAPPER: list[Rule] = [
    Rule(rule_id=rid, action=verdict, pattern=pat, detail=detail)
    for rid, pat, detail, verdict in _PATTERNS
]

__all__ = ["FICTIONAL_WRAPPER"]
