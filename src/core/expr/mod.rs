/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, time::Duration};

use regex::Regex;

pub mod parser;
pub mod tokenizer;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Expression {
    pub items: Vec<ExpressionItem>,
}

#[derive(Debug, Clone)]
pub enum ExpressionItem {
    Variable(u32),
    Capture(u32),
    Global(String),
    Constant(Constant),
    BinaryOperator(BinaryOperator),
    UnaryOperator(UnaryOperator),
    Regex(Regex),
    JmpIf { val: bool, pos: u32 },
    Function { id: u32, num_args: u32 },
    ArrayAccess,
    ArrayBuild(u32),
}

#[derive(Debug)]
pub enum Variable<'x> {
    String(Cow<'x, str>),
    Integer(i64),
    Float(f64),
    Array(Vec<Variable<'x>>),
}

impl Default for Variable<'_> {
    fn default() -> Self {
        Variable::Integer(0)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Constant {
    Integer(i64),
    Float(f64),
    String(String),
}

impl Eq for Constant {}

impl From<String> for Constant {
    fn from(value: String) -> Self {
        Constant::String(value)
    }
}

impl From<bool> for Constant {
    fn from(value: bool) -> Self {
        Constant::Integer(value as i64)
    }
}

impl From<i64> for Constant {
    fn from(value: i64) -> Self {
        Constant::Integer(value)
    }
}

impl From<i32> for Constant {
    fn from(value: i32) -> Self {
        Constant::Integer(value as i64)
    }
}

impl From<i16> for Constant {
    fn from(value: i16) -> Self {
        Constant::Integer(value as i64)
    }
}

impl From<f64> for Constant {
    fn from(value: f64) -> Self {
        Constant::Float(value)
    }
}

impl From<usize> for Constant {
    fn from(value: usize) -> Self {
        Constant::Integer(value as i64)
    }
}

#[allow(clippy::type_complexity)]
pub(super) const FUNCTIONS: &[(&str, u32)] = &[
    ("count", 1),
    ("sort", 2),
    ("dedup", 1),
    ("winnow", 1),
    ("is_intersect", 2),
    ("is_email", 1),
    ("email_part", 2),
    ("is_empty", 1),
    ("is_number", 1),
    ("is_ip_addr", 1),
    ("is_ipv4_addr", 1),
    ("is_ipv6_addr", 1),
    ("ip_reverse_name", 1),
    ("trim", 1),
    ("trim_end", 1),
    ("trim_start", 1),
    ("len", 1),
    ("to_lowercase", 1),
    ("to_uppercase", 1),
    ("is_uppercase", 1),
    ("is_lowercase", 1),
    ("has_digits", 1),
    ("count_spaces", 1),
    ("count_uppercase", 1),
    ("count_lowercase", 1),
    ("count_chars", 1),
    ("contains", 2),
    ("contains_ignore_case", 2),
    ("eq_ignore_case", 2),
    ("starts_with", 2),
    ("ends_with", 2),
    ("lines", 1),
    ("substring", 3),
    ("strip_prefix", 2),
    ("strip_suffix", 2),
    ("split", 2),
    ("rsplit", 2),
    ("split_once", 2),
    ("rsplit_once", 2),
    ("split_n", 3),
    ("split_words", 1),
    ("is_local_domain", 2),
    ("is_local_address", 2),
    ("key_get", 2),
    ("key_exists", 2),
    ("key_set", 3),
    ("counter_incr", 3),
    ("counter_get", 2),
    ("dns_query", 2),
    ("sql_query", 3),
    ("hash", 2),
    ("if_then", 3),
];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,

    And,
    Or,
    Xor,

    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UnaryOperator {
    Not,
    Minus,
}

#[derive(Debug, Clone)]
pub enum Token {
    Variable(u32),
    Global(String),
    Capture(u32),
    Function {
        name: Cow<'static, str>,
        id: u32,
        num_args: u32,
    },
    Constant(Constant),
    Regex(Regex),
    BinaryOperator(BinaryOperator),
    UnaryOperator(UnaryOperator),
    OpenParen,
    CloseParen,
    OpenBracket,
    CloseBracket,
    Comma,
}

impl From<usize> for Variable<'_> {
    fn from(value: usize) -> Self {
        Variable::Integer(value as i64)
    }
}

impl From<i64> for Variable<'_> {
    fn from(value: i64) -> Self {
        Variable::Integer(value)
    }
}

impl From<i32> for Variable<'_> {
    fn from(value: i32) -> Self {
        Variable::Integer(value as i64)
    }
}

impl From<i16> for Variable<'_> {
    fn from(value: i16) -> Self {
        Variable::Integer(value as i64)
    }
}

impl From<f64> for Variable<'_> {
    fn from(value: f64) -> Self {
        Variable::Float(value)
    }
}

impl<'x> From<&'x str> for Variable<'x> {
    fn from(value: &'x str) -> Self {
        Variable::String(Cow::Borrowed(value))
    }
}

impl From<String> for Variable<'_> {
    fn from(value: String) -> Self {
        Variable::String(Cow::Owned(value))
    }
}

impl<'x> From<Vec<Variable<'x>>> for Variable<'x> {
    fn from(value: Vec<Variable<'x>>) -> Self {
        Variable::Array(value)
    }
}

impl From<bool> for Variable<'_> {
    fn from(value: bool) -> Self {
        Variable::Integer(value as i64)
    }
}

impl<T: Into<Constant>> From<T> for Expression {
    fn from(value: T) -> Self {
        Expression {
            items: vec![ExpressionItem::Constant(value.into())],
        }
    }
}

impl PartialEq for ExpressionItem {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Variable(l0), Self::Variable(r0)) => l0 == r0,
            (Self::Constant(l0), Self::Constant(r0)) => l0 == r0,
            (Self::BinaryOperator(l0), Self::BinaryOperator(r0)) => l0 == r0,
            (Self::UnaryOperator(l0), Self::UnaryOperator(r0)) => l0 == r0,
            (Self::Regex(_), Self::Regex(_)) => true,
            (
                Self::JmpIf {
                    val: l_val,
                    pos: l_pos,
                },
                Self::JmpIf {
                    val: r_val,
                    pos: r_pos,
                },
            ) => l_val == r_val && l_pos == r_pos,
            (
                Self::Function {
                    id: l_id,
                    num_args: l_num_args,
                },
                Self::Function {
                    id: r_id,
                    num_args: r_num_args,
                },
            ) => l_id == r_id && l_num_args == r_num_args,
            (Self::ArrayBuild(l0), Self::ArrayBuild(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl Eq for ExpressionItem {}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Variable(l0), Self::Variable(r0)) => l0 == r0,
            (
                Self::Function {
                    name: l_name,
                    id: l_id,
                    num_args: l_num_args,
                },
                Self::Function {
                    name: r_name,
                    id: r_id,
                    num_args: r_num_args,
                },
            ) => l_name == r_name && l_id == r_id && l_num_args == r_num_args,
            (Self::Constant(l0), Self::Constant(r0)) => l0 == r0,
            (Self::Regex(_), Self::Regex(_)) => true,
            (Self::BinaryOperator(l0), Self::BinaryOperator(r0)) => l0 == r0,
            (Self::UnaryOperator(l0), Self::UnaryOperator(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl Eq for Token {}

pub trait ParseValue: Sized {
    fn parse_value(value: &str) -> Option<Self>;
}

impl ParseValue for Duration {
    fn parse_value(value: &str) -> Option<Self> {
        let duration = value.trim_end().to_ascii_lowercase();
        let (num, multiplier) = if let Some(num) = duration.strip_suffix('d') {
            (num, 24 * 60 * 60 * 1000)
        } else if let Some(num) = duration.strip_suffix('h') {
            (num, 60 * 60 * 1000)
        } else if let Some(num) = duration.strip_suffix('m') {
            (num, 60 * 1000)
        } else if let Some(num) = duration.strip_suffix("ms") {
            (num, 1)
        } else if let Some(num) = duration.strip_suffix('s') {
            (num, 1000)
        } else {
            (duration.as_str(), 1)
        };
        num.trim().parse::<u64>().ok().and_then(|num| {
            if num > 0 {
                Some(Duration::from_millis(num * multiplier))
            } else {
                None
            }
        })
    }
}
