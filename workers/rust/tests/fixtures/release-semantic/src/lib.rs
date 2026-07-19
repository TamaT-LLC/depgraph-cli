pub struct Input {
    pub value: u32,
}

pub struct Output {
    pub value: u32,
}

pub fn transform(input: Input) -> Output {
    Output { value: input.value }
}

pub fn build(input: Input) -> Output {
    transform(input)
}

pub fn cycle_left(value: u32) -> u32 {
    if value == 0 {
        0
    } else {
        cycle_right(value - 1)
    }
}

pub fn cycle_right(value: u32) -> u32 {
    if value == 0 {
        0
    } else {
        cycle_left(value - 1)
    }
}
