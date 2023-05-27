use crate::{
    halo2_proofs::{
        circuit::{Cell, Value},
        plonk::Error,
    },
    util::arithmetic::{CurveAffine, FieldExt},
};
use std::{fmt::Debug, ops::Deref};

pub trait Context: Debug {
    fn constrain_equal(&mut self, lhs: Cell, rhs: Cell) -> Result<(), Error>;

    fn offset(&self) -> usize;
}

/// Instructions to handle field element operations.
pub trait IntegerInstructions<'a, F: FieldExt>: Clone + Debug {
    /// Context (either enhanced `region` or some kind of builder).
    type Context: Context;
    /// Assigned cell.
    type AssignedCell: Clone + Debug;
    /// Assigned integer.
    type AssignedInteger: Clone + Debug;

    /// Assign an integer witness.
    fn assign_integer(
        &self,
        ctx: &mut Self::Context,
        integer: Value<F>, // witness
    ) -> Result<Self::AssignedInteger, Error>;

    /// Assign an integer constant.
    fn assign_constant(
        &self,
        ctx: &mut Self::Context,
        integer: F,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Sum integers with coefficients and constant.
    fn sum_with_coeff_and_const(
        &self,
        ctx: &mut Self::Context,
        values: &[(F::Scalar, impl Deref<Target = Self::AssignedInteger>)],
        constant: F::Scalar,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Sum product of integers with coefficients and constant.
    fn sum_products_with_coeff_and_const(
        &self,
        ctx: &mut Self::Context,
        values: &[(
            F::Scalar,
            impl Deref<Target = Self::AssignedInteger>,
            impl Deref<Target = Self::AssignedInteger>,
        )],
        constant: F::Scalar,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Returns `lhs - rhs`.
    fn sub(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedInteger,
        rhs: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Returns `-value`.
    fn neg(
        &self,
        ctx: &mut Self::Context,
        value: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Returns `1/value`.
    fn invert(
        &self,
        ctx: &mut Self::Context,
        value: &Self::AssignedInteger,
    ) -> Result<Self::AssignedInteger, Error>;

    /// Enforce `lhs` and `rhs` are equal.
    fn assert_equal(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedInteger,
        rhs: &Self::AssignedInteger,
    ) -> Result<(), Error>;
}

/// Instructions to handle elliptic curve point operations.
pub trait EccInstructions<'a, C: CurveAffine>: Clone + Debug {
    /// Context
    type Context: Context;
    /// [`IntegerInstructions`] to handle scalar field operation.
    type ScalarChip: IntegerInstructions<
        'a,
        C::Scalar,
        Context = Self::Context,
        AssignedCell = Self::AssignedCell,
        AssignedInteger = Self::AssignedScalar,
    >;
    /// Assigned cell.
    type AssignedCell: Clone + Debug;
    /// Assigned scalar field element.
    type AssignedScalar: Clone + Debug;
    /// Assigned elliptic curve point.
    type AssignedEcPoint: Clone + Debug;

    /// Returns reference of [`EccInstructions::ScalarChip`].
    fn scalar_chip(&self) -> &Self::ScalarChip;

    /// Assign a elliptic curve point constant.
    fn assign_constant(
        &self,
        ctx: &mut Self::Context,
        ec_point: C,
    ) -> Result<Self::AssignedEcPoint, Error>;

    /// Assign a elliptic curve point witness.
    fn assign_point(
        &self,
        ctx: &mut Self::Context,
        ec_point: Value<C>,
    ) -> Result<Self::AssignedEcPoint, Error>;

    /// Sum elliptic curve points and constant.
    fn sum_with_const(
        &self,
        ctx: &mut Self::Context,
        values: &[impl Deref<Target = Self::AssignedEcPoint>],
        constant: C,
    ) -> Result<Self::AssignedEcPoint, Error>;

    /// Perform fixed base multi-scalar multiplication.
    fn fixed_base_msm(
        &mut self,
        ctx: &mut Self::Context,
        pairs: &[(impl Deref<Target = Self::AssignedScalar>, C)],
    ) -> Result<Self::AssignedEcPoint, Error>;

    /// Perform variable base multi-scalar multiplication.
    fn variable_base_msm(
        &mut self,
        ctx: &mut Self::Context,
        pairs: &[(
            impl Deref<Target = Self::AssignedScalar>,
            impl Deref<Target = Self::AssignedEcPoint>,
        )],
    ) -> Result<Self::AssignedEcPoint, Error>;

    /// Enforce `lhs` and `rhs` are equal.
    fn assert_equal(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedEcPoint,
        rhs: &Self::AssignedEcPoint,
    ) -> Result<(), Error>;
}

mod halo2_lib {
    use crate::{
        halo2_proofs::{
            circuit::{Cell, Value},
            halo2curves::CurveAffineExt,
            plonk::Error,
        },
        loader::halo2::{Context, EccInstructions, IntegerInstructions},
        util::arithmetic::{CurveAffine, Field},
    };
    use halo2_base::{
        gates::{flex_gate::FlexGateConfig, GateInstructions, RangeInstructions},
        utils::BigPrimeField as PrimeField,
        AssignedValue,
        QuantumCell::{Constant, Existing, Witness},
        {self},
    };
    use halo2_ecc::{
        bigint::CRTInteger,
        ecc::{fixed_base::FixedEcPoint, BaseFieldEccChip, EcPoint},
        fields::FieldChip,
    };
    use std::ops::Deref;

    type AssignedInteger<C> = CRTInteger<<C as CurveAffine>::ScalarExt>;
    type AssignedEcPoint<C> = EcPoint<<C as CurveAffine>::ScalarExt, AssignedInteger<C>>;

    impl<'a, F: PrimeField> Context for halo2_base::Context<'a, F> {
        fn constrain_equal(&mut self, lhs: Cell, rhs: Cell) -> Result<(), Error> {
            #[cfg(feature = "halo2-axiom")]
            self.region.constrain_equal(&lhs, &rhs)?;
            #[cfg(feature = "halo2-pse")]
            self.region.constrain_equal(lhs, rhs)?;
            Ok(())
        }

        fn offset(&self) -> usize {
            unreachable!()
        }
    }

    impl<'a, F: PrimeField> IntegerInstructions<'a, F> for FlexGateConfig<F> {
        type Context = halo2_base::Context<'a, F>;
        type AssignedCell = AssignedValue<F>;
        type AssignedInteger = AssignedValue<F>;

        fn assign_integer(
            &self,
            ctx: &mut Self::Context,
            integer: Value<F>,
        ) -> Result<Self::AssignedInteger, Error> {
            Ok(self.assign_region_last(ctx, vec![Witness(integer)], vec![]))
        }

        fn assign_constant(
            &self,
            ctx: &mut Self::Context,
            integer: F,
        ) -> Result<Self::AssignedInteger, Error> {
            Ok(self.assign_region_last(ctx, vec![Constant(integer)], vec![]))
        }

        fn sum_with_coeff_and_const(
            &self,
            ctx: &mut Self::Context,
            values: &[(F::Scalar, impl Deref<Target = Self::AssignedInteger>)],
            constant: F,
        ) -> Result<Self::AssignedInteger, Error> {
            let mut a = Vec::with_capacity(values.len() + 1);
            let mut b = Vec::with_capacity(values.len() + 1);
            if constant != F::zero() {
                a.push(Constant(constant));
                b.push(Constant(F::one()));
            }
            a.extend(values.iter().map(|(_, a)| Existing(a.deref().clone())));
            b.extend(values.iter().map(|(c, _)| Constant(*c)));
            Ok(self.inner_product(ctx, a, b))
        }

        fn sum_products_with_coeff_and_const(
            &self,
            ctx: &mut Self::Context,
            values: &[(
                F::Scalar,
                impl Deref<Target = Self::AssignedInteger>,
                impl Deref<Target = Self::AssignedInteger>,
            )],
            constant: F,
        ) -> Result<Self::AssignedInteger, Error> {
            match values.len() {
                0 => self.assign_constant(ctx, constant),
                _ => Ok(self.sum_products_with_coeff_and_var(
                    ctx,
                    values.iter().map(|(c, a, b)| {
                        (*c, Existing(a.deref().clone()), Existing(b.deref().clone()))
                    }),
                    Constant(constant),
                )),
            }
        }

        fn sub(
            &self,
            ctx: &mut Self::Context,
            a: &Self::AssignedInteger,
            b: &Self::AssignedInteger,
        ) -> Result<Self::AssignedInteger, Error> {
            Ok(GateInstructions::sub(self, ctx, Existing(a.clone()), Existing(b.clone())))
        }

        fn neg(
            &self,
            ctx: &mut Self::Context,
            a: &Self::AssignedInteger,
        ) -> Result<Self::AssignedInteger, Error> {
            Ok(GateInstructions::neg(self, ctx, Existing(a.clone())))
        }

        fn invert(
            &self,
            ctx: &mut Self::Context,
            a: &Self::AssignedInteger,
        ) -> Result<Self::AssignedInteger, Error> {
            // make sure scalar != 0
            let is_zero = self.is_zero(ctx, a);
            self.assert_is_const(ctx, &is_zero, F::zero());
            Ok(GateInstructions::div_unsafe(self, ctx, Constant(F::one()), Existing(a.clone())))
        }

        fn assert_equal(
            &self,
            ctx: &mut Self::Context,
            a: &Self::AssignedInteger,
            b: &Self::AssignedInteger,
        ) -> Result<(), Error> {
            ctx.region.constrain_equal(a.cell(), b.cell())
        }
    }

    impl<'a, C: CurveAffineExt> EccInstructions<'a, C> for BaseFieldEccChip<C>
    where
        C::ScalarExt: PrimeField,
        C::Base: PrimeField,
    {
        type Context = halo2_base::Context<'a, C::Scalar>;
        type ScalarChip = FlexGateConfig<C::Scalar>;
        type AssignedCell = AssignedValue<C::Scalar>;
        type AssignedScalar = AssignedValue<C::Scalar>;
        type AssignedEcPoint = AssignedEcPoint<C>;

        fn scalar_chip(&self) -> &Self::ScalarChip {
            self.field_chip.range().gate()
        }

        fn assign_constant(
            &self,
            ctx: &mut Self::Context,
            point: C,
        ) -> Result<Self::AssignedEcPoint, Error> {
            let fixed = FixedEcPoint::<C::Scalar, C>::from_curve(
                point,
                self.field_chip.num_limbs,
                self.field_chip.limb_bits,
            );
            Ok(FixedEcPoint::assign(
                fixed,
                self.field_chip(),
                ctx,
                self.field_chip().native_modulus(),
            ))
        }

        fn assign_point(
            &self,
            ctx: &mut Self::Context,
            point: Value<C>,
        ) -> Result<Self::AssignedEcPoint, Error> {
            let assigned = self.assign_point(ctx, point);
            let is_valid = self.is_on_curve_or_infinity::<C>(ctx, &assigned);
            self.field_chip.range.gate.assert_is_const(ctx, &is_valid, C::Scalar::one());
            Ok(assigned)
        }

        fn sum_with_const(
            &self,
            ctx: &mut Self::Context,
            values: &[impl Deref<Target = Self::AssignedEcPoint>],
            constant: C,
        ) -> Result<Self::AssignedEcPoint, Error> {
            let constant = if bool::from(constant.is_identity()) {
                None
            } else {
                let constant = EccInstructions::<C>::assign_constant(self, ctx, constant).unwrap();
                Some(constant)
            };
            let tmp = values.iter().map(|x| x.deref().clone()).collect::<Vec<_>>();
            let tmp = constant.iter().chain(tmp.iter());
            Ok(self.sum::<C>(ctx, tmp.cloned()))
        }

        fn variable_base_msm(
            &mut self,
            ctx: &mut Self::Context,
            pairs: &[(
                impl Deref<Target = Self::AssignedScalar>,
                impl Deref<Target = Self::AssignedEcPoint>,
            )],
        ) -> Result<Self::AssignedEcPoint, Error> {
            let (scalars, points): (Vec<_>, Vec<_>) = pairs
                .iter()
                .map(|(scalar, point)| (vec![scalar.deref().clone()], point.deref().clone()))
                .unzip();

            Ok(BaseFieldEccChip::<C>::variable_base_msm::<C>(
                self,
                ctx,
                &points,
                &scalars,
                C::Scalar::NUM_BITS as usize,
                4, // empirically clump factor of 4 seems to be best
            ))
        }

        fn fixed_base_msm(
            &mut self,
            ctx: &mut Self::Context,
            pairs: &[(impl Deref<Target = Self::AssignedScalar>, C)],
        ) -> Result<Self::AssignedEcPoint, Error> {
            let (scalars, points): (Vec<_>, Vec<_>) = pairs
                .iter()
                .filter_map(|(scalar, point)| {
                    if point.is_identity().into() {
                        None
                    } else {
                        Some((vec![scalar.deref().clone()], *point))
                    }
                })
                .unzip();

            Ok(BaseFieldEccChip::<C>::fixed_base_msm::<C>(
                self,
                ctx,
                &points,
                &scalars,
                C::Scalar::NUM_BITS as usize,
                0,
                4,
            ))
        }

        fn assert_equal(
            &self,
            ctx: &mut Self::Context,
            a: &Self::AssignedEcPoint,
            b: &Self::AssignedEcPoint,
        ) -> Result<(), Error> {
            self.assert_equal(ctx, a, b);
            Ok(())
        }
    }
}
