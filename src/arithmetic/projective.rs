//! Projective points

#![allow(clippy::op_ref)]

use core::{
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use elliptic_curve::{
    group::{
        ff::Field,
        prime::{PrimeCurve, PrimeCurveAffine, PrimeGroup},
        Curve, Group, GroupEncoding,
    },
    ops::LinearCombination,
    rand_core::RngCore,
    sec1::{FromEncodedPoint, ToEncodedPoint},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::DefaultIsZeroes,
    Error, PrimeCurveArithmetic, ProjectiveArithmetic, Result,
};

use super::{AffinePoint, FieldElement, Scalar, CURVE_EQUATION_B};
use crate::{CompressedPoint, EncodedPoint, NistP384, PublicKey};

impl ProjectiveArithmetic for NistP384 {
    type ProjectivePoint = ProjectivePoint;
}

impl PrimeCurveArithmetic for NistP384 {
    type CurveGroup = ProjectivePoint;
}

/// A point on the secP384r1 curve in projective coordinates.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(docsrs, doc(cfg(feature = "arithmetic")))]
pub struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl ProjectivePoint {
    /// Base point of P-384.
    pub const GENERATOR: Self = Self {
        x: AffinePoint::GENERATOR.x,
        y: AffinePoint::GENERATOR.y,
        z: FieldElement::ONE,
    };
    /// Additive identity of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    /// Returns the additive identity of P-384, also known as the "neutral
    /// element" or "point at infinity".
    #[deprecated(since = "0.10.1", note = "use `ProjectivePoint::IDENTITY` instead")]
    pub const fn identity() -> ProjectivePoint {
        Self::IDENTITY
    }

    /// Returns the base point of P-384.
    #[deprecated(since = "0.10.1", note = "use `ProjectivePoint::GENERATOR` instead")]
    pub fn generator() -> ProjectivePoint {
        Self::GENERATOR
    }

    /// Returns the affine representation of this point, or `None` if it is the
    /// identity.
    pub fn to_affine(&self) -> AffinePoint {
        self.z
            .invert()
            .map(|zinv| AffinePoint {
                x: self.x * &zinv,
                y: self.y * &zinv,
                infinity: 0,
            })
            .unwrap_or(AffinePoint::IDENTITY)
    }

    /// Returns `-self`.
    fn neg(&self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Returns `self + other`.
    fn add(&self, other: &ProjectivePoint) -> ProjectivePoint {
        // We implement the complete addition formula from Renes-Costello-Batina 2015
        // (https://eprint.iacr.org/2015/1060 Algorithm 4). The comments after each line
        // indicate which algorithm steps are being performed.

        let xx = self.x * &other.x; // 1
        let yy = self.y * &other.y; // 2
        let zz = self.z * &other.z; // 3
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) - &(xx + &yy); // 4, 5, 6, 7, 8
        let yz_pairs = ((self.y + &self.z) * &(other.y + &other.z)) - &(yy + &zz); // 9, 10, 11, 12, 13
        let xz_pairs = ((self.x + &self.z) * &(other.x + &other.z)) - &(xx + &zz); // 14, 15, 16, 17, 18

        let bzz_part = xz_pairs - &(CURVE_EQUATION_B * &zz); // 19, 20
        let bzz3_part = bzz_part.double() + &bzz_part; // 21, 22
        let yy_m_bzz3 = yy - &bzz3_part; // 23
        let yy_p_bzz3 = yy + &bzz3_part; // 24

        let zz3 = zz.double() + &zz; // 26, 27
        let bxz_part = (CURVE_EQUATION_B * &xz_pairs) - &(zz3 + &xx); // 25, 28, 29
        let bxz3_part = bxz_part.double() + &bxz_part; // 30, 31
        let xx3_m_zz3 = xx.double() + &xx - &zz3; // 32, 33, 34

        ProjectivePoint {
            x: (yy_p_bzz3 * &xy_pairs) - &(yz_pairs * &bxz3_part), // 35, 39, 40
            y: (yy_p_bzz3 * &yy_m_bzz3) + &(xx3_m_zz3 * &bxz3_part), // 36, 37, 38
            z: (yy_m_bzz3 * &yz_pairs) + &(xy_pairs * &xx3_m_zz3), // 41, 42, 43
        }
    }

    /// Returns `self + other`.
    fn add_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        // We implement the complete mixed addition formula from Renes-Costello-Batina
        // 2015 (Algorithm 5). The comments after each line indicate which algorithm
        // steps are being performed.

        let xx = self.x * &other.x; // 1
        let yy = self.y * &other.y; // 2
        let xy_pairs = ((self.x + &self.y) * &(other.x + &other.y)) - &(xx + &yy); // 3, 4, 5, 6, 7
        let yz_pairs = (other.y * &self.z) + &self.y; // 8, 9 (t4)
        let xz_pairs = (other.x * &self.z) + &self.x; // 10, 11 (y3)

        let bz_part = xz_pairs - &(CURVE_EQUATION_B * &self.z); // 12, 13
        let bz3_part = bz_part.double() + &bz_part; // 14, 15
        let yy_m_bzz3 = yy - &bz3_part; // 16
        let yy_p_bzz3 = yy + &bz3_part; // 17

        let z3 = self.z.double() + &self.z; // 19, 20
        let bxz_part = (CURVE_EQUATION_B * &xz_pairs) - &(z3 + &xx); // 18, 21, 22
        let bxz3_part = bxz_part.double() + &bxz_part; // 23, 24
        let xx3_m_zz3 = xx.double() + &xx - &z3; // 25, 26, 27

        let mut ret = ProjectivePoint {
            x: (yy_p_bzz3 * &xy_pairs) - &(yz_pairs * &bxz3_part), // 28, 32, 33
            y: (yy_p_bzz3 * &yy_m_bzz3) + &(xx3_m_zz3 * &bxz3_part), // 29, 30, 31
            z: (yy_m_bzz3 * &yz_pairs) + &(xy_pairs * &xx3_m_zz3), // 34, 35, 36
        };
        ret.conditional_assign(self, other.is_identity());
        ret
    }

    /// Doubles this point.
    pub fn double(&self) -> ProjectivePoint {
        // We implement the exception-free point doubling formula from
        // Renes-Costello-Batina 2015 (Algorithm 6). The comments after each line
        // indicate which algorithm steps are being performed.

        let xx = self.x.square(); // 1
        let yy = self.y.square(); // 2
        let zz = self.z.square(); // 3
        let xy2 = (self.x * &self.y).double(); // 4, 5
        let xz2 = (self.x * &self.z).double(); // 6, 7

        let bzz_part = (CURVE_EQUATION_B * &zz) - &xz2; // 8, 9
        let bzz3_part = bzz_part.double() + &bzz_part; // 10, 11
        let yy_m_bzz3 = yy - &bzz3_part; // 12
        let yy_p_bzz3 = yy + &bzz3_part; // 13
        let y_frag = yy_p_bzz3 * &yy_m_bzz3; // 14
        let x_frag = yy_m_bzz3 * &xy2; // 15

        let zz3 = zz.double() + &zz; // 16, 17
        let bxz2_part = (CURVE_EQUATION_B * &xz2) - &(zz3 + &xx); // 18, 19, 20
        let bxz6_part = bxz2_part.double() + &bxz2_part; // 21, 22
        let xx3_m_zz3 = xx.double() + &xx - &zz3; // 23, 24, 25

        let y = y_frag + &(xx3_m_zz3 * &bxz6_part); // 26, 27
        let yz2 = (self.y * &self.z).double(); // 28, 29
        let x = x_frag - &(bxz6_part * &yz2); // 30, 31
        let z = (yz2 * &yy).double().double(); // 32, 33, 34

        ProjectivePoint { x, y, z }
    }

    /// Returns `self - other`.
    fn sub(&self, other: &ProjectivePoint) -> ProjectivePoint {
        self.add(&other.neg())
    }

    /// Returns `self - other`.
    fn sub_mixed(&self, other: &AffinePoint) -> ProjectivePoint {
        self.add_mixed(&other.neg())
    }

    /// Returns `[k] self`.
    fn mul(&self, k: &Scalar) -> ProjectivePoint {
        let mut pc = [ProjectivePoint::default(); 16];
        pc[0] = ProjectivePoint::IDENTITY;
        pc[1] = *self;
        for i in 2..16 {
            pc[i] = if i % 2 == 0 {
                pc[i / 2].double()
            } else {
                pc[i - 1].add(self)
            };
        }
        let mut q = ProjectivePoint::IDENTITY;
        let k = k.to_bytes();
        let mut pos = 384 - 4;
        loop {
            let slot = (k[47 - (pos >> 3) as usize] >> (pos & 7)) & 0xf;
            let mut t = ProjectivePoint::IDENTITY;
            for i in 1..16 {
                t.conditional_assign(
                    &pc[i],
                    Choice::from(((slot as usize ^ i).wrapping_sub(1) >> 8) as u8 & 1),
                );
            }
            q = q.add(&t);
            if pos == 0 {
                break;
            }
            q = q.double().double().double().double();
            pos -= 4;
        }
        q
    }
}

impl Group for ProjectivePoint {
    type Scalar = Scalar;

    fn random(mut rng: impl RngCore) -> Self {
        Self::GENERATOR * Scalar::random(&mut rng)
    }

    fn identity() -> Self {
        Self::IDENTITY
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::IDENTITY)
    }

    #[must_use]
    fn double(&self) -> Self {
        ProjectivePoint::double(self)
    }
}

impl GroupEncoding for ProjectivePoint {
    type Repr = CompressedPoint;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <AffinePoint as GroupEncoding>::from_bytes(bytes).map(Into::into)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        // No unchecked conversion possible for compressed points
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.to_affine().to_bytes()
    }
}

impl PrimeGroup for ProjectivePoint {}

impl Curve for ProjectivePoint {
    type AffineRepr = AffinePoint;

    fn to_affine(&self) -> AffinePoint {
        ProjectivePoint::to_affine(self)
    }
}

impl PrimeCurve for ProjectivePoint {
    type Affine = AffinePoint;
}

impl LinearCombination for ProjectivePoint {}

impl From<AffinePoint> for ProjectivePoint {
    fn from(p: AffinePoint) -> Self {
        let projective = ProjectivePoint {
            x: p.x,
            y: p.y,
            z: FieldElement::ONE,
        };
        Self::conditional_select(&projective, &Self::IDENTITY, p.is_identity())
    }
}

impl From<&AffinePoint> for ProjectivePoint {
    fn from(p: &AffinePoint) -> Self {
        Self::from(*p)
    }
}

impl From<ProjectivePoint> for AffinePoint {
    fn from(p: ProjectivePoint) -> AffinePoint {
        p.to_affine()
    }
}

impl From<&ProjectivePoint> for AffinePoint {
    fn from(p: &ProjectivePoint) -> AffinePoint {
        p.to_affine()
    }
}

impl FromEncodedPoint<NistP384> for ProjectivePoint {
    fn from_encoded_point(p: &EncodedPoint) -> CtOption<Self> {
        AffinePoint::from_encoded_point(p).map(ProjectivePoint::from)
    }
}

impl ToEncodedPoint<NistP384> for ProjectivePoint {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        self.to_affine().to_encoded_point(compress)
    }
}

impl ConditionallySelectable for ProjectivePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ProjectivePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl ConstantTimeEq for ProjectivePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_affine().ct_eq(&other.to_affine())
    }
}

impl DefaultIsZeroes for ProjectivePoint {}

impl Eq for ProjectivePoint {}

impl PartialEq for ProjectivePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Default for ProjectivePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl Add<ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(&self, &other)
    }
}

impl Add<&ProjectivePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(self, other)
    }
}

impl Add<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::add(&self, other)
    }
}

impl AddAssign<ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: ProjectivePoint) {
        *self = ProjectivePoint::add(self, &rhs);
    }
}

impl AddAssign<&ProjectivePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: &ProjectivePoint) {
        *self = ProjectivePoint::add(self, rhs);
    }
}

impl Add<AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(&self, &other)
    }
}

impl Add<&AffinePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(self, other)
    }
}

impl Add<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn add(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::add_mixed(&self, other)
    }
}

impl AddAssign<AffinePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: AffinePoint) {
        *self = ProjectivePoint::add_mixed(self, &rhs);
    }
}

impl AddAssign<&AffinePoint> for ProjectivePoint {
    fn add_assign(&mut self, rhs: &AffinePoint) {
        *self = ProjectivePoint::add_mixed(self, rhs);
    }
}

impl Sum for ProjectivePoint {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(ProjectivePoint::IDENTITY, |a, b| a + b)
    }
}

impl<'a> Sum<&'a ProjectivePoint> for ProjectivePoint {
    fn sum<I: Iterator<Item = &'a ProjectivePoint>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl Sub<ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(&self, &other)
    }
}

impl Sub<&ProjectivePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(self, other)
    }
}

impl Sub<&ProjectivePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &ProjectivePoint) -> ProjectivePoint {
        ProjectivePoint::sub(&self, other)
    }
}

impl SubAssign<ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: ProjectivePoint) {
        *self = ProjectivePoint::sub(self, &rhs);
    }
}

impl SubAssign<&ProjectivePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: &ProjectivePoint) {
        *self = ProjectivePoint::sub(self, rhs);
    }
}

impl Sub<AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(&self, &other)
    }
}

impl Sub<&AffinePoint> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(self, other)
    }
}

impl Sub<&AffinePoint> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn sub(self, other: &AffinePoint) -> ProjectivePoint {
        ProjectivePoint::sub_mixed(&self, other)
    }
}

impl SubAssign<AffinePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: AffinePoint) {
        *self = ProjectivePoint::sub_mixed(self, &rhs);
    }
}

impl SubAssign<&AffinePoint> for ProjectivePoint {
    fn sub_assign(&mut self, rhs: &AffinePoint) {
        *self = ProjectivePoint::sub_mixed(self, rhs);
    }
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: Scalar) -> ProjectivePoint {
        ProjectivePoint::mul(&self, &other)
    }
}

impl Mul<&Scalar> for &ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        ProjectivePoint::mul(self, other)
    }
}

impl Mul<&Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, other: &Scalar) -> ProjectivePoint {
        ProjectivePoint::mul(&self, other)
    }
}

impl MulAssign<Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = ProjectivePoint::mul(self, &rhs);
    }
}

impl MulAssign<&Scalar> for ProjectivePoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = ProjectivePoint::mul(self, rhs);
    }
}

impl Neg for ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> ProjectivePoint {
        ProjectivePoint::neg(&self)
    }
}

impl<'a> Neg for &'a ProjectivePoint {
    type Output = ProjectivePoint;

    fn neg(self) -> ProjectivePoint {
        ProjectivePoint::neg(self)
    }
}

impl From<PublicKey> for ProjectivePoint {
    fn from(public_key: PublicKey) -> ProjectivePoint {
        AffinePoint::from(public_key).into()
    }
}

impl From<&PublicKey> for ProjectivePoint {
    fn from(public_key: &PublicKey) -> ProjectivePoint {
        AffinePoint::from(public_key).into()
    }
}

impl TryFrom<ProjectivePoint> for PublicKey {
    type Error = Error;

    fn try_from(point: ProjectivePoint) -> Result<PublicKey> {
        AffinePoint::from(point).try_into()
    }
}

impl TryFrom<&ProjectivePoint> for PublicKey {
    type Error = Error;

    fn try_from(point: &ProjectivePoint) -> Result<PublicKey> {
        AffinePoint::from(point).try_into()
    }
}
