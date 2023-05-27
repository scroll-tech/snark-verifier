use halo2_base::{
    halo2_proofs::{
        halo2curves::bn256::{Fq, Fr, G1Affine},
        plonk::{Column, ConstraintSystem, Expression, Instance},
    },
    utils::modulus,
};
use snark_verifier::loader::halo2::halo2_ecc::{
    ecc::{BaseFieldEccChip, EccChip},
    fields::fp::{FpConfig, FpStrategy},
};
use zkevm_circuits::util::{Challenges, SubCircuitConfig};

use crate::{BITS, LIMBS};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
/// Parameters for aggregation circuit configs.
pub struct AggregationConfigParams {
    pub strategy: FpStrategy,
    pub degree: u32,
    pub num_advice: Vec<usize>,
    pub num_lookup_advice: Vec<usize>,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

#[derive(Clone, Debug)]
/// Configurations for aggregation circuit
pub struct AggregationConfig {
    /// Non-native field chip configurations
    pub base_field_config: FpConfig<Fr, Fq>,
    /// Instance for public input
    pub instance: Column<Instance>,
}

impl AggregationConfig {
    /// Build a configuration from parameters.
    pub fn configure(meta: &mut ConstraintSystem<Fr>, params: AggregationConfigParams) -> Self {
        assert!(
            params.limb_bits == BITS && params.num_limbs == LIMBS,
            "For now we fix limb_bits = {}, otherwise change code",
            BITS
        );
        let base_field_config = FpConfig::configure(
            meta,
            params.strategy,
            &params.num_advice,
            &params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits,
            BITS,
            LIMBS,
            modulus::<Fq>(),
            0,
            params.degree as usize,
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self { base_field_config, instance }
    }

    /// Range gate configuration
    pub fn range(&self) -> &halo2_base::gates::range::RangeConfig<Fr> {
        &self.base_field_config.range
    }

    /// Flex gate configuration
    pub fn gate(&self) -> &halo2_base::gates::flex_gate::FlexGateConfig<Fr> {
        &self.base_field_config.range.gate
    }

    /// Ecc gate configuration
    pub fn ecc_chip(&self) -> BaseFieldEccChip<G1Affine> {
        EccChip::construct(self.base_field_config.clone())
    }
}

/// Auxiliary arguments for AggregationCircuit's Config
#[derive(Clone, Debug)]
pub struct AggregationConfigArgs<Fr> {
    pub param: AggregationConfigParams,
    pub challenges: Challenges<Expression<Fr>>,
}

impl SubCircuitConfig<Fr> for AggregationConfig {
    type ConfigArgs = AggregationConfigArgs<Fr>;

    /// Return a new AggregationConfig
    fn new(meta: &mut ConstraintSystem<Fr>, config_args: Self::ConfigArgs) -> Self {
        Self::configure(meta, config_args.param)
    }
}
