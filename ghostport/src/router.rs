use crate::config::{Config, RuleConfig};

#[derive(Debug, PartialEq)]
pub enum RoutingDecision<'a> {
    Matched(&'a RuleConfig),
    DefaultBlock,
}

pub fn match_route<'a>(path: &str, config: &'a Config) -> RoutingDecision<'a> {
    let mut best_match: Option<&'a RuleConfig> = None;

    for rule in &config.rules {
        if path.starts_with(&rule.path) {
            match best_match {
                None => best_match = Some(rule),
                Some(current_best) => {
                    if rule.path.len() > current_best.path.len() {
                        best_match = Some(rule);
                    }
                }
            }
        }
    }

    match best_match {
        Some(rule) => RoutingDecision::Matched(rule),
        None => RoutingDecision::DefaultBlock,
    }
}