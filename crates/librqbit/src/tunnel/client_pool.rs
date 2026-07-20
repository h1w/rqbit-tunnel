/// Pick the index of the least-loaded available carrier.
///
/// `loads[i] == None` means carrier `i` is currently unavailable (not
/// connected). Returns `None` if no carrier is available. Ties break toward the
/// lowest index for determinism.
pub(crate) fn select_carrier(loads: &[Option<usize>]) -> Option<usize> {
    loads
        .iter()
        .enumerate()
        .filter_map(|(i, load)| load.map(|l| (i, l)))
        .min_by_key(|&(i, load)| (load, i))
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::select_carrier;

    #[test]
    fn none_when_empty() {
        assert_eq!(select_carrier(&[]), None);
    }

    #[test]
    fn none_when_all_unavailable() {
        assert_eq!(select_carrier(&[None, None]), None);
    }

    #[test]
    fn picks_minimum_load() {
        assert_eq!(select_carrier(&[Some(3), Some(1), Some(2)]), Some(1));
    }

    #[test]
    fn ties_break_to_lowest_index() {
        assert_eq!(select_carrier(&[Some(2), Some(2)]), Some(0));
    }

    #[test]
    fn skips_unavailable_carriers() {
        assert_eq!(select_carrier(&[None, Some(5), None, Some(4)]), Some(3));
    }
}
