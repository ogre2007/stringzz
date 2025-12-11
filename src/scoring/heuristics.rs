use crate::{
    TokenInfo,
    regex_base::{REGEX_INSENSITIVE, REGEX_SENSITIVE, RegexRules},
};

fn filter_rg(tok: &mut TokenInfo, regex_base: &RegexRules, _ignore_case: bool) {
    let mut score_local = 0;
    let mut cats: Vec<String> = vec![];

    for (category, regexes) in regex_base {
        let mut found = false;

        for (re, score) in regexes {
            if re.is_match(&tok.reprz) {
                score_local += score;
                found = true;
            }
        }

        if found {
            cats.push(category.to_string());
        }
    }

    tok.score += score_local;
    tok.add_note(cats.join(", "));
}

pub fn score_with_regex(tok: &mut TokenInfo) {
    filter_rg(tok, &REGEX_INSENSITIVE, true);

    filter_rg(tok, &REGEX_SENSITIVE, false);
}
