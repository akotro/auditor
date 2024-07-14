use std::iter;

use crate::parser;

fn get_trigrams(s: &str) -> Vec<(char, char, char)> {
    let it_1 = iter::once(' ').chain(iter::once(' ')).chain(s.chars());
    let it_2 = iter::once(' ').chain(s.chars());
    let it_3 = s.chars().chain(iter::once(' '));

    let res: Vec<(char, char, char)> = it_1
        .zip(it_2)
        .zip(it_3)
        .map(|((a, b), c): ((char, char), char)| (a, b, c))
        .collect();
    res
}

fn fuzzy_compare(a: &str, b: &str) -> f32 {
    let string_len = a.chars().count() + 1;

    let trigrams_a = get_trigrams(a);
    let trigrams_b = get_trigrams(b);

    let mut acc: f32 = 0.0f32;

    for t_a in &trigrams_a {
        for t_b in &trigrams_b {
            if t_a == t_b {
                acc += 1.0f32;
                break;
            }
        }
    }
    let res = acc / (string_len as f32);

    if (0.0f32..=1.0f32).contains(&res) {
        res
    } else {
        0.0f32
    }
}

pub fn fuzzy_search_best_n<'a>(
    s: &'a str,
    list: &'a [parser::AuditLogResponse],
    n: usize,
) -> Vec<&'a parser::AuditLogResponse> {
    let mut res: Vec<(&'a parser::AuditLogResponse, f32)> = list
        .iter()
        .map(|log| {
            let score = fuzzy_compare(s, &log.command);
            (log, score)
        })
        .collect();

    res.sort_by(|(_, d1), (_, d2)| d2.partial_cmp(d1).unwrap());

    res.into_iter().take(n).map(|(log, _)| log).collect()
}
