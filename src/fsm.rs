use std::marker::PhantomData;
use crate::Cell;

pub (crate) trait State {

    fn transition(&self, input: &Cell) -> Option<Box<dyn State>>;
    fn output(&self, input: &Cell) -> Option<Cell>;

}

pub (crate) struct FSM {

    state: Box<dyn State>,
}

unsafe impl Send for FSM {

}

impl FSM {

    pub (crate) fn new() -> Self {
        Self {
            state: Box::new(crate::state::Start),
        }
    }

    pub (crate) fn transition(& mut self, input: &Cell) {
        if let Some(new_state) = self.state.transition(input) {
            self.state = new_state
        }
    }

    pub (crate) fn output(&self, input: &Cell) -> Option<Cell> {
        self.state.output(input)
    }

}
